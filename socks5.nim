##
## SOCKS 5 library
##
## https://tools.ietf.org/html/rfc1928
## https://tools.ietf.org/html/rfc1929

import asyncnet,
  asyncdispatch,
  strutils,
  streams

from net import IpAddress, `$`
from net import parseIpAddress
from net import IpAddressFamily

const SOCKS_ver = 5.char

type
  Socks5RequestCommand* {.pure.} = enum
    Connect = 1, Bind = 2, UdpAssoc = 3

  Socks5AddressType* {.pure.} = enum
    IPv4 = 1, FQDN = 3, IPv6 = 4

  Socks5AuthMethod* {.pure.} = enum
    NoAuth = 0
    GSSAPI = 1
    UsernamePassword = 2
    NoAcceptableMethod = 0xff

  Socks5Request* = object
    cmd*: Socks5RequestCommand
    address_type*: Socks5AddressType
    ipaddress*: IpAddress
    fqdn*: string
    address*: string
    port*: Port

  Socks5ReplyType* {.pure.} = enum
    succeeded = 0, server_failure = 1,
    connection_not_allowed = 2, network_unreachable = 3,
    host_unreachable = 4, connection_refused = 5,
    ttl_expired = 6, command_not_supported = 7,
    address_type_not_supported = 8

  VarLenString* = object
    fieldlen*: uint8
    value*: string

  Socks5Reply* = object
    version*: uint8
    reply_type*: Socks5ReplyType
    reserved: uint8
    address_type*: Socks5AddressType
    server_bound_address*: VarLenString
    server_bound_port*: Port

  Socks5Error* = object of CatchableError
  Socks5AuthFailedError* = object of Socks5Error
  Socks5VersionError* = object of Socks5Error

proc recv1(s: AsyncSocket): Future[char] {.async.} =
  let b = await s.recv(1)
  return b[0]

proc recv1int(s: AsyncSocket): Future[int] {.async.} =
  let b = await s.recv(1)
  return b[0].uint8.int


proc receive_initial_negotiation*(client: AsyncSocket): Future[seq[Socks5AuthMethod]] {.async.} =
  ## Server: receive initial negotiation request
  ## Returns a sequence of accepted authentication methods
  echo "receive_initial_negotiation"
  let ver = await client.recv1()
  if ver != SOCKS_ver:
    raise newException(Socks5VersionError,  "Unsupported SOCKS version")

  let nmethods = (await client.recv(1))[0].int
  let methods = await client.recv(nmethods)
  result = @[]
  for m in methods:
    result.add Socks5AuthMethod(m)

proc receive_username_password*(s: AsyncSocket): Future[(string, string)] {.async.} =
  ## Receive (username, password) from client
  ## +----+------+----------+------+----------+
  ## |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
  ## +----+------+----------+------+----------+
  ## | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
  ## +----+------+----------+------+----------+
  let ver = await s.recv1()
  if ver != '\1':
    raise newException(Socks5VersionError,  "Unsupported Auth version")
  let ulen = await s.recv1int()
  let username = await s.recv(ulen)
  let plen = await s.recv1int()
  let password = await s.recv(plen)
  return (username, password)

proc send_username_password_auth_status*(s: AsyncSocket, success: bool) {.async.} =
  ## Send the authentication success or failure status
  if success:
    await s.send('\1' & '\0')
  else:
    await s.send('\1' & '\1')


proc parse_port(bytes: string): Port =
  Port(cast[uint16](bytes[0]) shl 8 + cast[uint16](bytes[1]))

proc parse_request*(s: AsyncSocket): Future[Socks5Request] {.async.} =
  ## Server: Parse SOCKS5 request
  ## +----+-----+-------+------+----------+----------+
  ## |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  ## +----+-----+-------+------+----------+----------+
  ## | 1  |  1  | X'00' |  1   | Variable |    2     |
  ## +----+-----+-------+------+----------+----------+
  ## Either the fqdn or ipaddress field is set in the return value.
  ## For convenience, the address field (string) is always set
  if (await s.recv1) != SOCKS_ver:
    raise newException(Socks5VersionError,  "Unsupported SOCKS version")

  result.cmd = Socks5RequestCommand(await s.recv1int)
  discard await s.recv1int  # RSV
  result.address_type = Socks5AddressType(await s.recv1int)
  case result.address_type
  of Socks5AddressType.IPv4:
    result.ipaddress = IpAddress(family: IpAddressFamily.IPv4)
    for n in 0..3:
      let oc = await s.recv1
      result.ipaddress.address_v4[n] = oc.uint8
    result.address = $(result.ipaddress)

  of Socks5AddressType.IPv6:
    result.ipaddress = IpAddress(family: IpAddressFamily.IPv6)
    for n in 0..15:
      let oc = await s.recv1
      result.ipaddress.address_v6[n] = oc.uint8
    result.address = $(result.ipaddress)

  of FQDN:
    let fqdn_len = await s.recv1int
    result.fqdn = await s.recv(fqdn_len)
    result.address = result.fqdn

  result.port = parse_port(await s.recv(2))


proc send_reply*(s: AsyncSocket, address_type: Socks5AddressType, server_ipaddr: IpAddress, server_port: Port) {.async.} =
  ## Server: Send reply
  ## +----+-----+-------+------+----------+----------+
  ## |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  ## +----+-----+-------+------+----------+----------+
  ## | 1  |  1  | X'00' |  1   | Variable |    2     |
  ## +----+-----+-------+------+----------+----------+
  var reply = repeat('\x00', 256 + 6)
  # version
  reply[0] = SOCKS_ver
  # reply_type
  reply[1] = Socks5ReplyType.succeeded.char
  # reserved
  reply[2] = '\0'
  #  address_type
  reply[3] = address_type.char
  reply[3] = '\x01'
  let addrlen = 4
  #for x in 0..<addrlen:
  #  reply[x + 4] = server_ipaddr.address_v4[x].char
  #var p = cast[uint16](server_port)
  #reply[4 + addrlen] = (p shr 1).char
  #reply[5 + addrlen] = (p and 0x0f).char
  reply.setLen(6 + addrlen)
  await s.send(reply)


# proc receive_udp(s: AsyncSocket) =
#   # +----+------+------+----------+----------+----------+
#   # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
#   # +----+------+------+----------+----------+----------+
#   # | 2  |  1   |  1   | Variable |    2     | Variable |
#   # +----+------+------+----------+----------+----------+
#   discard


proc socks5_request*(listener: AsyncSocket): Future[(AsyncSocket, Socks5Request)] {.async.} =
  ## Wait for an incoming connection, handle it without authentication
  let client = await listener.accept()
  let auth_methods = await receive_initial_negotiation(client)
  if not (auth_methods.contains Socks5AuthMethod.NoAuth):
    raise newException(Socks5Error, "Unsupported Auth")

  await client.send SOCKS_ver & Socks5AuthMethod.NoAuth.char
  let request = await parse_request(client)
  return (client, request)

proc socks5_request_user_pass*(
    listener: AsyncSocket,
    upc:proc (u,p: string): bool,
  ): Future[(AsyncSocket, Socks5Request)] {.async.} =
  ## Wait for an incoming connection, handle it with using username/password auth
  ## The upc proc is a callback to verify the credentials and return
  ## success/failure as a boolean.
  let client = await listener.accept()
  let methods = await receive_initial_negotiation(client)
  if not (methods.contains Socks5AuthMethod.UsernamePassword):
    raise newException(Socks5Error, "Unsupported Auth")

  await client.send SOCKS_ver & Socks5AuthMethod.UsernamePassword.char
  let (username, password) = await receive_username_password(client)
  # Call authorization callback
  let auth_ok = upc(username, password)
  await client.send_username_password_auth_status(auth_ok)
  if not auth_ok:
    raise newException(Socks5AuthFailedError, "Failed User/Pass Auth")

  let request = await parse_request(client)
  return (client, request)


# Demo server

when defined(demo):

  proc setup_listener*(port: Port): AsyncSocket =
    ### Setup TCP listener
    result = newAsyncSocket(buffered=false)
    result.setSockOpt(OptReuseAddr, true)
    result.bindAddr(port)
    result.listen()

  proc demo_username_password_check(username, password: string): bool =
    # cleartext password and timing attack: good only for a demo
    return (username == "user" and password == "pass")

  proc demo_forward(src, dst: AsyncSocket) {.async.} =
    ## Forward traffic between sockets
    while true:
      if src.isClosed():
        break
      let data = await src.recv(4096)
      if data == "" or dst.isClosed():
        break
      await dst.send(data)

  proc demo_server(
      port = 1080.Port,
      server_ipaddr = parseIpAddress("0.0.0.0"),
      server_port = 0.Port,
    ) {.async.} =
    ## A demo SOCKS5 server
    let listener = setup_listener(port)
    while true:
      try:
        let (client, request) = await socks5_request(listener)

        # Replace this chunk
        echo "connecting to ", request.address
        let uplink = newAsyncSocket()
        await uplink.connect(request.address, request.port)
        # end

        await client.send_reply(request.address_type, server_ipaddr, server_port)

        # Replace this chunk
        asyncCheck demo_forward(client, uplink)
        asyncCheck demo_forward(uplink, client)
        # end

      except:
        echo getCurrentExceptionMsg()

  proc demo_server_user_pass(
      port = 1080.Port,
      server_ipaddr = parseIpAddress("0.0.0.0"),
      server_port = 0.Port,
    ) {.async.} =
    ## A demo SOCKS5 with user/pass authentication
    let listener = setup_listener(port)
    while true:
      try:
        let (client, request) = await socks5_request_user_pass(listener, demo_username_password_check)
        await client.send_reply(request.address_type, server_ipaddr, server_port)
        await client.send("bye")
        client.close()
      except Socks5AuthFailedError:
        continue
      except:
        echo getCurrentExceptionMsg()

  proc main() =
    asyncCheck demo_server(port=9876.Port)
    asyncCheck demo_server_user_pass(port=9877.Port)
    runForever()

  if isMainModule:
    main()
