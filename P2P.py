import json
import AES_ENCRYPTION
from tcp_by_size import send_with_size, recv_by_size
import socket
import base64


def SendHELLO(sock: socket, info_hash, peer_id, bitfield=None, rsa_public_key: bytes = None):  #when downloader send its without bitfield so default is None
    message = {
        "type": "HELLO",
        "info_hash": info_hash,
        "peer_id": peer_id
    }
    if bitfield:
        message["bitfield"] = bitfield
    if rsa_public_key:
        b64_enc_rsa_pub = base64.b64encode(rsa_public_key).decode()
        message["public_key"] = b64_enc_rsa_pub

    ser_mes = json.dumps(message)
    send_with_size(sock, ser_mes.encode())


def RecvHELLO(sock: socket):
    ser_enc_mes = recv_by_size(sock)
    if ser_enc_mes == b'':
        return ser_enc_mes
    ser_mes = ser_enc_mes.decode()
    dict_mes = json.loads(ser_mes)
    return dict_mes


def Send_And_Encrypt_Request_Piece(sock, info_hash, index: int, block_size: int, current_offset: int,aes_session_key):
    message_dict = {"type": "REQUEST_PIECE",
                    "info_hash": info_hash,
                    "index": index,
                    "block_size": block_size,
                    "current_offset": current_offset}
    ser_mes = json.dumps(message_dict)
    final_mes = ser_mes.encode()
    enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(final_mes,aes_session_key)
    send_with_size(sock, enc_mes)


def Recv_And_Decrypt_Request_Piece(sock: socket,aes_session_key) -> dict:
    enc_bdata_ser_mes = recv_by_size(sock)
    if enc_bdata_ser_mes != b'':
        bdata_ser_mes = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_bdata_ser_mes,aes_session_key)
        ser_mes = bdata_ser_mes.decode()
        mes = json.loads(ser_mes)
        return mes
    return enc_bdata_ser_mes


def Send_And_Encrypt_Give_Piece(sock: socket, bdata_content: bytes, info_hash: str, index: int, block_size: int,
                    current_offset: int,aes_session_key):
    b64_enc_content = base64.b64encode(bdata_content).decode()
    message_dict = {"type": "GIVE_PIECE",
                    "info_hash": info_hash,
                    "index": index,
                    "block_size": block_size,
                    "current_offset": current_offset,
                    "b64_content": b64_enc_content}
    json_ser = json.dumps(message_dict)
    final_mes = json_ser.encode()
    print("ready to encrypt...")
    print(final_mes)
    enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(final_mes,aes_session_key)
    print(enc_mes)
    send_with_size(sock, enc_mes)


def Recv_And_Decrypt_Give_Piece(sock: socket,aes_session_key) -> dict:
    enc_bdata_recv = recv_by_size(sock)
    if enc_bdata_recv != b'':
        bdata_recv = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_bdata_recv,aes_session_key)
        dict_recv_data = bdata_recv.decode()
        dict_recv_data = json.loads(dict_recv_data)
        b64_enc_content = dict_recv_data.get("b64_content")
        bdata_content = base64.b64decode(b64_enc_content)
        dict_recv_data["bdata_content"] = bdata_content
        del dict_recv_data["b64_content"]
        return dict_recv_data

    return enc_bdata_recv


def Send_RSA_Enc_AES_Session_Key(sock: socket, rsa_enc_aes_key_pem: bytes):
    b64_rsa_enc_aes_key = base64.b64encode(rsa_enc_aes_key_pem).decode()
    mes_to_send = {"type": "SESSION_KEY",
                   "enc_session_key": b64_rsa_enc_aes_key}
    json_ser_mes = json.dumps(mes_to_send)
    print("in P2P Send_RSA_Enc_AES_Session_Key")
    print(json_ser_mes)
    send_with_size(sock, json_ser_mes.encode())


def Recv_RSA_Enc_Aes_Session_Key(sock) -> dict:
    json_ser_enc = recv_by_size(sock)
    if json_ser_enc != b'':
        json_mes = json_ser_enc.decode()
        mes = json.loads(json_mes)
        return mes

    return json_ser_enc
