import base64
import math
import os
import select
import socket
import json
import hashlib
import time
import tkinter as tk
from tkinter import messagebox, ttk
import win32api
import win32process
import threading
import ctypes

import AES_ENCRYPTION
import RSA_ENCRYPTION
from tcp_by_size import send_with_size, recv_by_size
import struct
import P2P
from Crypto.PublicKey import RSA

TRACKER_IP = "192.168.1.247"
TRACKER_PORT = 5000
SLEEPING_STATUS_UPDATE = 30
SELECTED_FILE = ""
SELECTED_FILE_LOCK = threading.Lock()
TORRENT_FILES_DIRECTORY = ".TORRENT_FILES"
CURRENT_DOWNLOAD_FILE_PATH = ""
CURRENT_DOWNLOAD_FILE_PATH_LOCK = threading.Lock()
CURRENT_FILE_LOCK = threading.Lock()
TORRENTS_DB = {}
TORRENTS_DB_LOCK = threading.Lock()
CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK = threading.Lock()
PEER_ID = ""
BLOCK_SIZE = 100 * 1024
SEED_PORT = 1234
MAX_PEERS_DOWNLOADING = 5
SEED_DIRECTORY = "SEED"
SEEDING_PATH_LOCK = threading.Lock()
CNT_DOWNLOADED_PIECES = 0
CNT_DOWNLOADED_PIECES_LOCK = threading.Lock()
UPDATE_PROGRESS_BAR_TIME = 300  #in miliseconds
REQUEST_PEERS_AGAIN_TIME = 60
PROGRESS_BAR = None
PROGRESS_BAR_WINDOW = None
DONE_DOWNLOAD = False
DONE_DOWNLOAD_LOCK = threading.Lock()
PUBLIC_KEY_PATH = "CLIENT_RSA_KEYS\\public_key.pem"
PRIVATE_KEY_PATH = "CLIENT_RSA_KEYS\\private_key.pem"

class SmartBitfield:
    def __init__(self, length, max_peers_downloading):
        self.length = length
        self.max_peers_downloading = max_peers_downloading
        self.pieces = ["not started"] * length
        self.download = [{"download": 0} for index in range(length)]
        self.done = "done"

    def download_piece(self, index):
        self.download[index]["download"] += 1
        self.pieces[index] = self.download[index]

    def Can_Download(self, index):
        return self.download[index]["download"] < self.max_peers_downloading and self.pieces[index] != self.done

    def FinishPiece(self, index):
        self.pieces[index] = self.done

    def Is_Piece_Done(self, index):
        return self.pieces[index] == self.done

    def Failed_Download(self, index):
        if self.download[index]["download"] > 0:
            self.download[index]["download"] -= 1
            self.pieces[index] = self.download[index]

    def Is_All_Done(self):
        for index in self.pieces:
            if index != self.done:
                return False
        return True

    def __repr__(self):
        return ", ".join(str(index) for index in self.pieces)


CURRENT_DOWNLOAD_FILE_SMART_BITFIELD: SmartBitfield


def Recv_Peers_From_Tracker(sock: socket, json_sent_mes):
    request_message = json.loads(json_sent_mes)

    json_ser_mes = recv_by_size(sock)
    recv_mes = json.loads(json_ser_mes)  #returns dictionary
    print(recv_mes)
    message_type = Get_Type_Message(recv_mes)
    Peers_to_connect = []
    if message_type == "send_peers":
        if request_message["info_hash"] == recv_mes["info_hash"]:
            print("same info hash! ready to go")
            Peers_to_connect = recv_mes["peers"]
            print(Peers_to_connect)
            if Peers_to_connect:
                print("there is peers")
            else:
                print("no peers have this file currently")

    return Peers_to_connect


def show_progress_bar(total_pieces):
    global PROGRESS_BAR
    global PROGRESS_BAR_WINDOW

    PROGRESS_BAR_WINDOW = tk.Tk()
    PROGRESS_BAR_WINDOW.title("Downloading...")
    PROGRESS_BAR_WINDOW.geometry("400x100")

    label = tk.Label(PROGRESS_BAR_WINDOW, text="Downloading file...", font=("Courier", 12))
    label.pack(pady=10)

    PROGRESS_BAR = tk.DoubleVar()
    progressbar_widget = ttk.Progressbar(PROGRESS_BAR_WINDOW, variable=PROGRESS_BAR, maximum=100, length=300)
    progressbar_widget.pack(pady=5)

    PROGRESS_BAR_WINDOW.after(UPDATE_PROGRESS_BAR_TIME, update_progress_bar_loop, total_pieces)

    PROGRESS_BAR_WINDOW.mainloop()


def update_progress_bar_loop(total_pieces):
    global PROGRESS_BAR
    global CNT_DOWNLOADED_PIECES
    global CNT_DOWNLOADED_PIECES_LOCK

    with CNT_DOWNLOADED_PIECES_LOCK:
        percent_to_put = (CNT_DOWNLOADED_PIECES / total_pieces) * 100
        done = CNT_DOWNLOADED_PIECES >= total_pieces

    if PROGRESS_BAR:
        PROGRESS_BAR.set(percent_to_put)

    if not done:
        PROGRESS_BAR_WINDOW.after(UPDATE_PROGRESS_BAR_TIME, update_progress_bar_loop, total_pieces)
    else:
        for widget in PROGRESS_BAR_WINDOW.winfo_children():
            widget.destroy()

        PROGRESS_BAR_WINDOW.title("Download Complete")
        PROGRESS_BAR_WINDOW.geometry("300x150")
        PROGRESS_BAR_WINDOW.configure(bg="#e0ffe0")

        label = tk.Label(PROGRESS_BAR_WINDOW, text="✅ Download Successful!",
                         font=("Helvetica", 14), bg="#e0ffe0", fg="green")
        label.pack(pady=20)

        close_btn = tk.Button(PROGRESS_BAR_WINDOW, text="OK", width=10,
                              command=PROGRESS_BAR_WINDOW.destroy)
        close_btn.pack(pady=10)


def Download_From_Peers(peer_list: list, torrent_file_path, tracker_sock: socket):
    global CURRENT_DOWNLOAD_FILE_PATH
    global CURRENT_DOWNLOAD_FILE_PATH_LOCK
    global CURRENT_FILE_LOCK
    global CURRENT_DOWNLOAD_FILE_SMART_BITFIELD
    global CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK
    global PEER_ID
    global DONE_DOWNLOAD
    global DONE_DOWNLOAD_LOCK

    file_name = input("enter file name to download to ")
    with CURRENT_DOWNLOAD_FILE_PATH_LOCK:
        while os.path.exists(file_name):
            print("file " + str(file_name) + " already exists")
            file_name = input("enter file name to download to ")

        CURRENT_DOWNLOAD_FILE_PATH = file_name

    torrent_info_dict = Get_Info_Dictionary_From_Torrent_File(torrent_file_path)
    info_hash = Get_Info_Hash_From_Torrent_File(torrent_file_path)
    pieces = torrent_info_dict.get("Pieces")
    amount_of_pieces = len(pieces)

    with CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK:
        CURRENT_DOWNLOAD_FILE_SMART_BITFIELD = SmartBitfield(amount_of_pieces, MAX_PEERS_DOWNLOADING)

    while not DONE_DOWNLOAD:
        with CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK:
            is_done_temp = CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.Is_All_Done()

        if not is_done_temp:
            for peer in peer_list:
                print("peer to connect ====== ")
                print(peer)
                threading.Thread(target=Download_From_Peer, args=(peer,)).start()

            time.sleep(REQUEST_PEERS_AGAIN_TIME)
            json_request_message = Request_Peers_From_Tracker(tracker_sock, info_hash, PEER_ID)
            peer_list = Recv_Peers_From_Tracker(tracker_sock, json_request_message)


        else:
            print("done!")
            with DONE_DOWNLOAD_LOCK:
                DONE_DOWNLOAD = True


def Download_From_Peer(peer: dict):
    global SELECTED_FILE
    global PEER_ID
    global CURRENT_DOWNLOAD_FILE_SMART_BITFIELD
    global MAX_PEERS_DOWNLOADING
    global CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK
    global CNT_DOWNLOADED_PIECES
    global CNT_DOWNLOADED_PIECES_LOCK
    seeder_ip = peer.get("peer_ip")
    seeder_port = peer.get("peer_port")
    seeder_id = peer.get("peer_id")
    torrent_file_path = TORRENT_FILES_DIRECTORY + "\\" + SELECTED_FILE
    torrent_file_info_dict = Get_Info_Dictionary_From_Torrent_File(torrent_file_path)
    chunk_size = torrent_file_info_dict.get("Piece size")
    print(torrent_file_info_dict)

    info_hash = Get_Info_Hash_From_Torrent_File(torrent_file_path)
    download_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    download_sock.settimeout(10)
    try:
        download_sock.connect((seeder_ip, seeder_port))
        print("connected successfully to ")
        print(seeder_ip)
        print(seeder_id)
        print(seeder_port)
        print("on downloader side")

        aes_session_key = AES_ENCRYPTION.Generate_AES_CBC_256_Bit_Key()
        print("AES SESSION KEY ------- ")
        print(aes_session_key)
        #generate aes session key
        P2P.SendHELLO(download_sock, info_hash, PEER_ID)
        dict_recv_mes = P2P.RecvHELLO(download_sock)
        print("recv HELLO from seeder")
        print(dict_recv_mes)
        #send and recv HELLO handshake with seeder
        b64_rsa_public_key_pem = dict_recv_mes.get("public_key")
        #base64 decoding the rsa public key
        rsa_public_key_pem = base64.b64decode(b64_rsa_public_key_pem)

        rsa_public_key = RSA.import_key(rsa_public_key_pem)
        rsa_enc_aes_session_key = RSA_ENCRYPTION.rsa_encrypt(aes_session_key,rsa_public_key)
        #get rsa public key from the server(seeder) and encrypt the aes session key with it
        P2P.Send_RSA_Enc_AES_Session_Key(download_sock, rsa_enc_aes_session_key)

        print(dict_recv_mes)
        seeders_bitfield = dict_recv_mes.get("bitfield")
        print("seeders bitfield : " + seeders_bitfield)

        list_of_pieces_hash = torrent_file_info_dict.get("Pieces")
        amount_of_pieces = len(torrent_file_info_dict.get("Pieces"))

        for index in range(len(seeders_bitfield)):
            can_download = False
            can_save = False
            print(repr(CURRENT_DOWNLOAD_FILE_SMART_BITFIELD))
            if seeders_bitfield[index] == "1":
                CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK.acquire()
                if CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.Can_Download(index):
                    can_download = True
                    CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.download_piece(index)
                CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK.release()

                if can_download:
                    downloaded_piece = Download_Piece(download_sock, info_hash, torrent_file_info_dict, index, aes_session_key)
                    if Verify_Downloaded_Piece(downloaded_piece, list_of_pieces_hash[index]):
                        #verify the piece hash with the piece hash from the torrent file
                        print(index)
                        CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK.acquire()
                        if not CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.Is_Piece_Done(index):
                            CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.FinishPiece(index)
                            can_save = True
                        CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK.release()
                        if can_save:
                            Write_Piece_To_File(downloaded_piece, index, chunk_size)
                            Write_Piece_To_Seed_Folder(downloaded_piece, index, info_hash)
                            with CNT_DOWNLOADED_PIECES_LOCK:
                                CNT_DOWNLOADED_PIECES += 1
                    else:
                        with CURRENT_DOWNLOAD_FILE_SMART_BITFIELD_LOCK:
                            CURRENT_DOWNLOAD_FILE_SMART_BITFIELD.Failed_Download(index)



    except ConnectionError:
        print("not able to connect to " + str(seeder_ip) + " , " + str(peer_port))
    except TimeoutError:
        print("timeout has passed limit")
    except Exception as e:
        print(e)
    download_sock.close()


def Write_Piece_To_Seed_Folder(downloaded_piece: bytes, index, info_hash):
    global SEED_DIRECTORY
    global SEEDING_PATH_LOCK
    print("in Write Piece to SEED folder!")
    dir_to_look = SEED_DIRECTORY + "\\" + info_hash
    with SEEDING_PATH_LOCK:
        if not os.path.exists(dir_to_look):
            os.mkdir(dir_to_look)

    hash_of_piece = hashlib.sha256(downloaded_piece).hexdigest()
    target_dir_to_write = dir_to_look + "\\" + str(index) + "_" + str(hash_of_piece)
    print(target_dir_to_write)
    with open(target_dir_to_write, "wb") as piece_file:
        piece_file.write(downloaded_piece)


def Write_Piece_To_File(downloaded_piece: bytes, index: int, chunk_size):
    global CURRENT_FILE_LOCK
    global CURRENT_DOWNLOAD_FILE_PATH
    print("in write piece to file")
    seek_var = index * chunk_size
    CURRENT_FILE_LOCK.acquire()
    if not os.path.exists(CURRENT_DOWNLOAD_FILE_PATH):
        with open(CURRENT_DOWNLOAD_FILE_PATH, "w+b") as f:
            f.close()
    with open(CURRENT_DOWNLOAD_FILE_PATH, "r+b") as target_file:
        target_file.seek(seek_var)
        target_file.write(downloaded_piece)
    CURRENT_FILE_LOCK.release()


def Verify_Downloaded_Piece(downloaded_piece: bytes, piece_hash):
    hash_of_piece = hashlib.sha256(downloaded_piece).hexdigest()
    print(hash_of_piece)
    return piece_hash == hash_of_piece


def Download_Piece(download_sock: socket, info_hash: str, info_torrent_dict: dict, index: int,aes_session_key) -> bytes:
    global BLOCK_SIZE
    print("in download piece func!!!")
    chunk_size = info_torrent_dict.get("Piece size")
    current_offset = 0
    chunk_content = b""
    while current_offset < chunk_size:
        P2P.Send_And_Encrypt_Request_Piece(download_sock, info_hash, index, BLOCK_SIZE, current_offset,aes_session_key)
        recvd_give_piece = P2P.Recv_And_Decrypt_Give_Piece(download_sock,aes_session_key)
        block_chunk_content = recvd_give_piece.get("bdata_content")
        chunk_content += block_chunk_content
        current_offset += BLOCK_SIZE

    return chunk_content



def Seed_Thread_Func():
    global SEED_PORT
    global PUBLIC_KEY_PATH
    global PRIVATE_KEY_PATH
    rsa_keys = RSA_ENCRYPTION.Generate_And_Save_Rsa_Keys_In_Disk_PEM(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH)

    seed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    seed_sock.bind(("0.0.0.0", SEED_PORT))
    seed_sock.listen(50)

    socket_list = [seed_sock]
    while True:
        rlist, _, _ = select.select(socket_list, [], [], None)

        for rsocket in rlist:

            if rsocket == seed_sock:

                downloader_sock, downloader_addr = rsocket.accept()
                socket_list.append(downloader_sock)
                print("new connection from " + str(downloader_addr))
            else:
                Handle_Downloading_Peer(rsocket, socket_list,rsa_keys)


def Handle_Downloading_Peer(download_sock: socket, read_sockets_list: list,rsa_keys : tuple):
    global PEER_ID

    dict_hello_mes = P2P.RecvHELLO(download_sock)
    if dict_hello_mes == b'':
        read_sockets_list.remove(download_sock)
        download_sock.close()
    else:
        private_rsa_key = rsa_keys[0]
        public_rsa_key = rsa_keys[1]
        pem_public_rsa_key = public_rsa_key.export_key()
        print("on seeder side")
        print(dict_hello_mes)
        requested_info_hash = dict_hello_mes.get("info_hash")
        print(requested_info_hash)
        requested_file_bitfield = Get_Bit_Field(requested_info_hash)

        P2P.SendHELLO(download_sock, requested_info_hash, PEER_ID, requested_file_bitfield,pem_public_rsa_key)
        enc_aes_session_key_dict_mes = P2P.Recv_RSA_Enc_Aes_Session_Key(download_sock)

        b64_enc_aes_session_key = enc_aes_session_key_dict_mes.get("enc_session_key")

        #base 64 decode to the aes session key
        enc_aes_session_key = base64.b64decode(b64_enc_aes_session_key)
        #getting the aes session key encrypted with the rsa seeder's public key
        aes_session_key = RSA_ENCRYPTION.rsa_decrypt(enc_aes_session_key, private_rsa_key)
        print("normal aes session key : " + str(aes_session_key))
        Give_Pieces(download_sock, requested_info_hash,aes_session_key)


def Give_Pieces(sock: socket, info_hash,aes_session_key):
    global SEED_DIRECTORY
    print("in Give piece func")
    print("AES SESSION KEY ------")
    print(aes_session_key)
    stop = False
    while not stop:
        recv_data = P2P.Recv_And_Decrypt_Request_Piece(sock,aes_session_key)
        if recv_data != b'':
            print(recv_data)
            chunk_index = recv_data.get("index")
            block_size = recv_data.get("block_size")
            current_offset = recv_data.get("current_offset")

            dir_to_look = SEED_DIRECTORY + "\\" + info_hash
            file_chunks = os.listdir(dir_to_look)
            chunk_name = ""
            for chunkname in file_chunks:
                if chunkname.startswith(str(chunk_index)):
                    chunk_name = chunkname

            chunk_dir = dir_to_look + "\\" + chunk_name

            with open(chunk_dir, "rb") as chunk:
                chunk_content = chunk.read()

            block_of_chunk = chunk_content[current_offset: current_offset + block_size]
            P2P.Send_And_Encrypt_Give_Piece(sock, block_of_chunk, info_hash, chunk_index, block_size, current_offset,aes_session_key)
        else:
            stop = True


def Start_Seed_Thread():
    seed_thread = threading.Thread(target=Seed_Thread_Func)
    seed_thread.start()


def Get_Type_Message(message_dictionary: dict):
    return message_dictionary.get("type", "0")


def Make_json_request_file(peer_id, info_hash):
    request_file_dict = {"type": "request file",
                         "peer_id": peer_id,
                         "info_hash": info_hash}
    print(request_file_dict)
    json_serialized_request = json.dumps(request_file_dict)
    return json_serialized_request


def Send_Status_To_Tracker(sock: socket, peer_id):
    global SEED_PORT
    #set priority to the lowest because this is for only sending status every 30 seconds
    handle = ctypes.windll.kernel32.GetCurrentThread()
    win32process.SetThreadPriority(handle, win32process.THREAD_PRIORITY_LOWEST)

    #put details in dictionary to send
    message_dict = {}
    message_dict["type"] = "status update"
    message_dict["peer_id"] = peer_id
    message_dict["port"] = SEED_PORT

    while True:  #sends every 30 seconds , dies when the main thread dies
        available_files = GetList_Of_All_Seed_Files_And_Bitfields()
        message_dict["available_files"] = available_files

        json_serialized_message = json.dumps(message_dict).encode()
        print(json_serialized_message)
        send_with_size(sock, json_serialized_message)
        time.sleep(SLEEPING_STATUS_UPDATE)


def GetList_Of_All_Seed_Files_And_Bitfields(torrent_files_directory=TORRENT_FILES_DIRECTORY):
    list_to_return = []
    files = os.listdir(torrent_files_directory)
    for torrent_file_name in files:  #add lock on this
        dict_file = {}
        torrent_file_path = torrent_files_directory + "\\" + torrent_file_name
        info_hash = Get_Info_Hash_From_Torrent_File(torrent_file_path)
        bit_field = Get_Bit_Field(info_hash)
        dict_file["info_hash"] = info_hash
        dict_file["bitfield"] = bit_field
        list_to_return.append(dict_file)

    return list_to_return


def determine_piece_size(file_size):
    if file_size <= 100 * 1024 * 1024:  # Small file (<=100MB)
        return 512 * 1024  # 512 KB
    elif file_size <= 1 * 1024 * 1024 * 1024:  # Medium file (<=1 GB)
        return 1 * 1024 * 1024  # 1 MB
    elif file_size <= 10 * 1024 * 1024 * 1024:  # Medium-Large file (<=10 GB)
        return 2 * 1024 * 1024  # 2 MB
    else:  # Large file (>10 GB)
        return 4 * 1024 * 1024


def get_hashes_for_chunks(file_path, file_size, piece_size) -> list:
    hashes_pieces = []
    with open(file_path, "rb") as file:
        while True:
            chunk_bytes = file.read(piece_size)
            if chunk_bytes == b"":
                break
            chunk_sha256 = hashlib.sha256(chunk_bytes).hexdigest()
            hashes_pieces.append(chunk_sha256)

    return hashes_pieces


def Make_Torrent_File_For_New_File(file_path, Want_To_Seed=True):
    global SEED_DIRECTORY
    torrent_file_dict = {}
    file_size = os.path.getsize(file_path)
    piece_size = determine_piece_size(file_size)

    hashes_chunks_list = get_hashes_for_chunks(file_path, file_size, piece_size)
    torrent_file_dict["File name"] = file_path
    torrent_file_dict["File size"] = file_size
    torrent_file_dict["Piece size"] = piece_size
    torrent_file_dict["Pieces"] = hashes_chunks_list
    print(torrent_file_dict)

    json_format_dict = json.dumps(torrent_file_dict)

    file_name_without_extention = os.path.splitext(os.path.basename(file_path))[0]
    torrent_file_path = TORRENT_FILES_DIRECTORY + "\\" + file_name_without_extention + ".torrent"
    print(torrent_file_path)
    with open(torrent_file_path, "wb") as torrent_file:
        torrent_file.write(json_format_dict.encode())

    if Want_To_Seed:
        hash_info = Get_Info_Hash_From_Torrent_File(torrent_file_path)
        print(hash_info)
        chunk_index = 0
        directory_path = SEED_DIRECTORY + "\\" + hash_info
        os.makedirs(directory_path, exist_ok=True)

        with open(file_path, "rb") as file_to_read:
            while True:
                chunk = file_to_read.read(piece_size)
                if chunk == b"":
                    break

                hash_chunk = hashlib.sha256(chunk).hexdigest()
                with open(SEED_DIRECTORY + "\\" + hash_info + "\\" + str(chunk_index) + "_" + hash_chunk,
                          "wb") as chunk_file:
                    chunk_file.write(chunk)

                chunk_index += 1


def Get_Info_Dictionary_From_Torrent_File(Torrent_File_Path):
    try:
        with open(Torrent_File_Path, "rb") as torrent_file:
            encoded_json_data = torrent_file.read()
    except Exception as e:
        print(e)
        return None

    dictionary_data = json.loads(encoded_json_data)
    return dictionary_data


def Get_Amount_Of_Pieces(piece_size, file_size):
    return math.ceil(file_size / piece_size)


def Get_Bit_Field(info_hash: str):
    global TORRENTS_DB
    global TORRENTS_DB_LOCK
    global SEED_DIRECTORY
    with TORRENTS_DB_LOCK:
        dictionary_info_file = TORRENTS_DB.get(info_hash)
    hash_chunks_list = dictionary_info_file.get("Pieces")
    file_size = dictionary_info_file.get("File size")
    piece_size = dictionary_info_file.get("Piece size")
    amount_of_pieces = Get_Amount_Of_Pieces(piece_size, file_size)
    bitfiled = ["0"] * amount_of_pieces
    direcroty_to_look = SEED_DIRECTORY + "\\" + info_hash
    seed_chunks = os.listdir(direcroty_to_look)
    for seed_chunk in seed_chunks:
        try:
            index_seed_chunk, hash_seed_chunk = seed_chunk.split("_")
        except Exception as e:
            print(e)
            continue
        if hash_seed_chunk in hash_chunks_list:
            bitfiled[int(index_seed_chunk)] = "1"
    return "".join(bitfiled)


def Get_Only_hashesFormatFile_From_Info_Hash_Directory(directory_to_look):
    files_in_directory = os.listdir(directory_to_look)
    return_list = []
    for file_name in files_in_directory:
        return_list.append(file_name.split("_")[1])

    return return_list


def Verify_Chunks_In_Disk():
    global SEED_DIRECTORY
    info_hashes_directories = os.listdir(SEED_DIRECTORY)
    for seed_info_hash in info_hashes_directories:
        chunks_files = os.listdir(SEED_DIRECTORY + "\\" + seed_info_hash)

        for file_name in chunks_files:
            with open(SEED_DIRECTORY + "\\" + seed_info_hash + "\\" + file_name, "rb") as f:
                chunk_data = f.read()

            hash_calculated = hashlib.sha256(chunk_data).hexdigest()
            correct_hash = file_name.split("_")[1]
            if hash_calculated != correct_hash:
                print("corrupted piece found!!")
                os.remove(SEED_DIRECTORY + "\\" + seed_info_hash + "\\" + file_name)
    print("done checking")


def Get_Info_Hash_From_Torrent_File(torrent_file_path) -> str:
    with open(torrent_file_path, "rb") as torrent_file:
        torrent_file_bdata = torrent_file.read()

    info_hash = hashlib.sha256(torrent_file_bdata).hexdigest()
    return info_hash


def create_low_priority_thread_status_update(sock: socket, peer_id):
    thread = threading.Thread(daemon=True, target=Send_Status_To_Tracker, args=(sock, peer_id))
    thread.start()
    print("thread started")


def pick_file_to_download():
    root = tk.Tk()
    root.title("Torrent Client")
    root.geometry("500x500")

    # Welcome label
    welcome_msg = ("hello torrent client...\n"
                   "To ask the tracker for files, put your .torrent file\n in the .TORRENT_FILES directory.\n"
                   "Here is your .TORRENT_FILES directory right now\n double click on the file you want to download")
    label = tk.Label(root, text=welcome_msg, justify=tk.LEFT, anchor="w", font=("Courier", 10))
    label.pack(padx=10, pady=10, anchor="w")

    frame = tk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=("Courier", 12))
    listbox.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    # Insert torrent files
    torrent_file_names = os.listdir(TORRENT_FILES_DIRECTORY)
    for file in torrent_file_names:
        listbox.insert(tk.END, file)

    # Double-click to trigger callback
    listbox.bind("<Double-Button-1>", lambda e: on_torrent_select(e, listbox, root))

    root.mainloop()


def on_torrent_select(event, list_box, root):
    global SELECTED_FILE
    global SELECTED_FILE_LOCK
    print(event)
    selection = list_box.curselection()
    if not selection:
        return
    file = list_box.get(selection[0])
    print(file)
    SELECTED_FILE_LOCK.acquire()
    SELECTED_FILE = file
    SELECTED_FILE_LOCK.release()
    root.destroy()


def load_all_torrents():
    global TORRENTS_DB
    global TORRENTS_DB_LOCK
    global TORRENT_FILES_DIRECTORY
    torrent_files = os.listdir(TORRENT_FILES_DIRECTORY)
    for file in torrent_files:
        torrent_file_path = TORRENT_FILES_DIRECTORY + "\\" + file
        info_dict = Get_Info_Dictionary_From_Torrent_File(torrent_file_path)
        info_hash = Get_Info_Hash_From_Torrent_File(torrent_file_path)
        with TORRENTS_DB_LOCK:
            TORRENTS_DB[info_hash] = info_dict

    print("success loading all torrents")


def Request_Peers_From_Tracker(sock: socket, info_hash, Peer_id) -> json:
    json_mes = Make_json_request_file(Peer_id, info_hash)
    print(json_mes)
    send_with_size(sock, json_mes.encode())
    return json_mes


if __name__ == "__main__":
    '''
    with open("a.txt","wb") as f:
        f.write(b"GIF" * 1000000)
    Make_Torrent_File_For_New_File("a.txt")
    '''
    Verify_Chunks_In_Disk()
    load_all_torrents()
    PEER_ID = input("enter peer id\n")

    peer_port = int(input("enter your port\n"))
    SEED_PORT = peer_port
    Start_Seed_Thread()
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((TRACKER_IP, TRACKER_PORT))
    bdata = recv_by_size(client_sock)
    print(bdata)
    create_low_priority_thread_status_update(client_sock, PEER_ID)
    while True:  #main loop

        while True:  #while file was not selected
            pick_file_to_download()
            SELECTED_FILE_LOCK.acquire()
            if SELECTED_FILE != "":
                SELECTED_FILE_LOCK.release()
                break
            SELECTED_FILE_LOCK.release()

        selected_torrent_file_path = TORRENT_FILES_DIRECTORY + "\\" + SELECTED_FILE
        print("selected file --- " + SELECTED_FILE)

        info_hash = Get_Info_Hash_From_Torrent_File(selected_torrent_file_path)
        info_dict_torrent = Get_Info_Dictionary_From_Torrent_File(selected_torrent_file_path)
        amount_of_pieces = len(info_dict_torrent.get("Pieces"))
        json_mes = Request_Peers_From_Tracker(client_sock, info_hash, PEER_ID)

        peers_to_connect = Recv_Peers_From_Tracker(client_sock, json_mes)
        print("peerssss")
        print(peers_to_connect)
        threading.Thread(target=Download_From_Peers,
                         args=(peers_to_connect, selected_torrent_file_path, client_sock)).start()
        show_progress_bar(amount_of_pieces)
