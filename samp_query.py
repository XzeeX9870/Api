import socket
import struct
import time

def decode_samp_string(data):
    charset = ''.join([chr(i) for i in range(128)]) + (
        '€�‚ƒ„…†‡�‰�‹�����‘’“”•–—�™�›���� ΅Ά£¤¥¦§¨©�«¬­®―°±²³΄µ¶·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�'
    )
    decoded = ''
    for b in data:
        index = b * 2
        if index + 1 < len(charset.encode('utf-16-le')):
            decoded += (charset.encode('utf-16-le')[index:index+2]).decode('utf-16-le')
    return decoded

def create_packet(host, port, opcode):
    ip_parts = list(map(int, host.split('.')))
    packet = b'SAMP' + bytes(ip_parts) + struct.pack('<H', port) + opcode.encode('ascii')
    return packet

def send_request(host, port, opcode, timeout, callback):
    packet = create_packet(host, port, opcode)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout / 1000)

    start_time = time.time()

    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
        end_time = time.time()
    except socket.timeout:
        return callback('Host unavailable', None)
    except Exception as e:
        return callback(str(e), None)
    finally:
        sock.close()

    ping = int((end_time - start_time) * 1000)

    if len(data) < 11:
        return callback('Invalid response', None)

    data = data[11:]
    offset = 0

    try:
        if opcode == 'i':
            passworded = data[offset]
            offset += 1
            players = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            maxplayers = struct.unpack_from('<H', data, offset)[0]
            offset += 2

            hostname_len = struct.unpack_from('<H', data, offset)[0]
            offset += 4
            hostname = decode_samp_string(data[offset:offset+hostname_len])
            offset += hostname_len

            gamemode_len = struct.unpack_from('<H', data, offset)[0]
            offset += 4
            gamemode = decode_samp_string(data[offset:offset+gamemode_len])
            offset += gamemode_len

            mapname_len = struct.unpack_from('<H', data, offset)[0]
            offset += 4
            mapname = decode_samp_string(data[offset:offset+mapname_len])
            offset += mapname_len

            result = {
                'passworded': passworded,
                'players': players,
                'maxplayers': maxplayers,
                'hostname': hostname,
                'gamemode': gamemode,
                'mapname': mapname,
                'ping': ping
            }
            return callback(None, result)

        elif opcode == 'r':
            rules = {}
            rulecount = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            for _ in range(rulecount):
                key_len = data[offset]
                offset += 1
                key = decode_samp_string(data[offset:offset+key_len])
                offset += key_len

                val_len = data[offset]
                offset += 1
                value = decode_samp_string(data[offset:offset+val_len])
                offset += val_len

                rules[key] = value
            return callback(None, rules)

        elif opcode == 'd':
            players = []
            playercount = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            for _ in range(playercount):
                player_id = data[offset]
                offset += 1
                name_len = data[offset]
                offset += 1
                name = decode_samp_string(data[offset:offset+name_len])
                offset += name_len
                score = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                ping = struct.unpack_from('<I', data, offset)[0]
                offset += 4

                players.append({
                    'id': player_id,
                    'name': name,
                    'score': score,
                    'ping': ping
                })
            return callback(None, players)

    except Exception as e:
        return callback(str(e), None)

def query_samp(options, callback):
    if isinstance(options, str):
        options = {'host': options}

    host = options.get('host')
    port = options.get('port', 7777)
    timeout = options.get('timeout', 1000)

    if not host:
        return callback('Invalid host', None)
    if not (1 <= port <= 65535):
        return callback('Invalid port', None)

    result = {'address': host}

    def handle_info(error, info):
        if error:
            return callback(error, None)

        result.update({
            'hostname': info['hostname'],
            'gamemode': info['gamemode'],
            'mapname': info['mapname'],
            'passworded': info['passworded'] == 1,
            'maxplayers': info['maxplayers'],
            'online': info['players'],
            'ping': info['ping']
        })

        def handle_rules(error, rules):
            if error:
                return callback(error, None)

            rules['lagcomp'] = (rules.get('lagcomp') == 'On')
            if 'weather' in rules:
                try:
                    rules['weather'] = int(rules['weather'])
                except:
                    pass

            result['rules'] = rules

            if result['online'] > 100:
                result['players'] = []
                return callback(None, result)

            def handle_players(error, players):
                if error:
                    return callback(error, None)

                result['players'] = players
                return callback(None, result)

            send_request(host, port, 'd', timeout, handle_players)

        send_request(host, port, 'r', timeout, handle_rules)

    send_request(host, port, 'i', timeout, handle_info)
