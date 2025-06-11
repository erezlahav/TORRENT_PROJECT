import json
import os.path
import socket
import threading
import time
from tcp_by_size import recv_by_size,send_with_size



LISTEN_AMOUNT = 100
LISTEN_PORT = 5000
TRACKER_DATA_BASE = {}
TRACKER_DATA_BASE_LOCK = threading.Lock()
TRACKER_DATA_BASE_DISK_LOCK = threading.Lock()
TRACKER_DATA_BASE_FILE_PATH = "JSON_DB.json"
SECONDS_TO_SAVE_DATA_BASE = 10
CLEAN_UP_THREAD_SLEEP = 3
PEER_TIMEOUT_THRESHOLD = 60
FIRST_RAREST_PEERS = 50

def handle_peer(peer_sock: socket, peer_addr):
    send_with_size(peer_sock,b"hiii")
    while True:
        Recv_And_process_peer_message(peer_sock,peer_addr)


def Recv_And_process_peer_message(peer_sock : socket, peer_adress: tuple):
    try:
        bdata_mes = recv_by_size(peer_sock)
        if not bdata_mes:
            print("peer " + str(peer_adress[0]) + " : " + str(peer_adress[1]) + " has exited")
            exit()
        peer_ip = peer_adress[0]
        deserialized_message = json.loads(bdata_mes.decode())
        dict_message = deserialized_message
        print(dict_message)
        message_type = Get_Type_Message(deserialized_message)

        if message_type == "status update":
            Update_Status_Of_Peer(dict_message, peer_ip)
        elif message_type == "request file":
            print("request file sent")
            Handle_Peer_Request_File(peer_sock, dict_message)

    except ConnectionResetError:
        print("peer " + str(peer_adress[0]) + " : " + str(peer_adress[1]) + " has exited")
        exit()


def Get_Type_Message(message_dictionary: dict):
    return message_dictionary.get("type")


def Handle_Peer_Request_File(peer_sock : socket, request_dict: dict):
    global TRACKER_DATA_BASE
    torrent_file_info_hash = request_dict.get("info_hash")
    peer_id = request_dict.get("peer_id")
    print(torrent_file_info_hash)

    peer_sorted_list = sort_by_rarity(torrent_file_info_hash,peer_id) #returns a list to peers sorted
    print(peer_sorted_list)
    message_to_send = Pack_Send_Peers_Message(peer_sorted_list,torrent_file_info_hash)
    print(message_to_send)
    json_ser_mes = json.dumps(message_to_send)
    send_with_size(peer_sock,json_ser_mes.encode())




def Exclude_peer(peer_sorted_list : list,peer_id):
    return [peer for peer in peer_sorted_list if peer.get("peer_id") != peer_id]

def Pack_Send_Peers_Message(peers_sorted_list : list, info_hash):
    global FIRST_RAREST_PEERS
    message_dict = {}
    message_dict["type"] = "send_peers"
    message_dict["info_hash"] = info_hash
    first_rarest_peers = peers_sorted_list[:FIRST_RAREST_PEERS]
    message_dict["peers"] = first_rarest_peers
    return message_dict


def sort_by_rarity(torrent_file_info_hash,peer_requested_id) -> list:  #returns a list of peers with the first index , the peer with the rarest piece
    global TRACKER_DATA_BASE
    peer_list = TRACKER_DATA_BASE.get(torrent_file_info_hash)

    dict_bits_frequency = count_piece_frequency(peer_list)
    bitfield_rarity_list = Build_Rarity_list(dict_bits_frequency)

    peers_scores_dict = Make_Dict_Scores_Peers(peer_list, bitfield_rarity_list)

    peers_ids_sorted_list = Build_Sort_Peer_id_List(peers_scores_dict)
    print(peers_ids_sorted_list)

    peer_list = TRACKER_DATA_BASE.get(torrent_file_info_hash) #get peer list again because peers might have disconnected

    peer_sorted_list = Build_Sort_Peer_List(peers_ids_sorted_list,peer_list)
    print(peer_sorted_list)
    peer_sorted_list_exclude_peer = Exclude_peer(peer_sorted_list, peer_requested_id)
    return peer_sorted_list_exclude_peer


def Make_Dict_Scores_Peers(peer_list: list, bitfield_rarity_list: list) -> dict:
    peers_scores_dict = {}
    for peer in peer_list:
        peer_score = 0
        score_bitfield = len(bitfield_rarity_list)
        peer_bitfield = peer.get("bitfield")
        for bitfield in bitfield_rarity_list:
            if peer_bitfield[int(bitfield)] == '1':
                peer_score += score_bitfield
            score_bitfield -= 1

        peers_scores_dict[peer.get("peer_id")] = peer_score


    return peers_scores_dict


def count_piece_frequency(peer_list: list) -> dict:
    dictionary_bits_count = {}
    for peer in peer_list:  #peer is a dictionary and peer_list is a list
        bit_index = 0
        bitfield = peer.get("bitfield")
        for bit in bitfield:  #bit is char and bitfield is string
            dictionary_bits_count[str(bit_index)] = dictionary_bits_count.get(str(bit_index), 0) + int(
                bit)  #increamenting the count of bit in this index by one
            #if key dont exist yet put zero(because get second parameter is the value to put if not exist)
            bit_index += 1

    return dictionary_bits_count


def Build_Rarity_list(dict_bits_frequency: dict):
    rarity_list = []
    while dict_bits_frequency != {}:
        min_bitfield_in_dict = Get_Rarest_bitfield(dict_bits_frequency)
        rarity_list.append(min_bitfield_in_dict)
        del dict_bits_frequency[min_bitfield_in_dict]

    return rarity_list


def Get_Rarest_bitfield(dict_bits_frequency: dict):
    min = float('inf')
    min_bitfield = None
    for bitfield in list(
            dict_bits_frequency.keys()):  #bitfiled is '1' char and dict_bits_frequency[bitfield] = (integer)
        if dict_bits_frequency[bitfield] < min:
            min = dict_bits_frequency[bitfield]
            min_bitfield = bitfield

    return min_bitfield


def Build_Sort_Peer_id_List(peers_scores_dict : dict) -> list:
    peer_sorted_list = []
    while peers_scores_dict != {}:
        max_score = -1
        max_peer_name = ""
        for peer in peers_scores_dict.keys():
            if peers_scores_dict[peer] > max_score:
                max_score = peers_scores_dict[peer]
                max_peer_name = peer

        peer_sorted_list.append(max_peer_name)
        del peers_scores_dict[max_peer_name]

    return peer_sorted_list



def Build_Sort_Peer_List(peers_ids_sorted_list : list, peer_list : list) -> list:

    final_sorted_peer_list = []
    for peer_id in peers_ids_sorted_list:
        peer = Find_Peer_By_Peer_id(peer_id,peer_list) #peer is dictionary
        final_sorted_peer_list.append(peer)

    return final_sorted_peer_list



def Find_Peer_By_Peer_id(peer_id, peer_list : list) -> dict:
    for peer in peer_list: #peer is dictionary
        curr_peer_id = peer.get("peer_id","0")
        if curr_peer_id != "0":
            if curr_peer_id == peer_id:
                return peer












def Update_Status_Of_Peer(message_dictionary: dict, peer_ip):
    global TRACKER_DATA_BASE
    global TRACKER_DATA_BASE_LOCK
    user_dict = {}
    peer_id = message_dictionary.get("peer_id")
    peer_listening_port = message_dictionary.get("port")
    available_files = message_dictionary.get("available_files")  #list of dictionaries
    user_dict["peer_id"] = peer_id
    user_dict["peer_ip"] = peer_ip
    user_dict["peer_port"] = peer_listening_port
    user_dict["last_seen"] = time.time()

    for peer_file in available_files:  #peer_file is dictionary of info hash and bitfield
        info_hash = peer_file.get("info_hash")
        bit_field = peer_file.get("bitfield")
        user_dict["bitfield"] = bit_field
        #TRACKER_DATA_BASE[info_hash] is a list of users that have this info hash
        TRACKER_DATA_BASE_LOCK.acquire()
        if not File_In_Data_Base(peer_file):
            TRACKER_DATA_BASE[info_hash] = []  #if this file hash is the first in the dictionary set the list to []

        peer_user_index = Peer_User_index_in_list(peer_id, TRACKER_DATA_BASE[info_hash])
        if peer_user_index != -1:  #if user is already in list, then remove the accurence before that
            TRACKER_DATA_BASE[info_hash].pop(peer_user_index)

        TRACKER_DATA_BASE[info_hash].append(user_dict)
        TRACKER_DATA_BASE_LOCK.release()
    print(TRACKER_DATA_BASE)


def Peer_User_index_in_list(peer_id, users_list) -> int:  #if not in list return -1, if in list return its index
    index = 0
    user_found_index = -1
    for user in users_list:
        if user.get("peer_id") == peer_id:
            user_found_index = index
        index += 1
    return user_found_index


def File_In_Data_Base(file: dict):  #returns true if file exist in tracker database
    global TRACKER_DATA_BASE
    is_good = TRACKER_DATA_BASE.get(file.get("info_hash")) is not None
    return is_good


def Get_Data_Base_From_Disk():
    global TRACKER_DATA_BASE
    global TRACKER_DATA_BASE_LOCK
    global TRACKER_DATA_BASE_DISK_LOCK
    global TRACKER_DATA_BASE_FILE_PATH
    if os.path.exists(TRACKER_DATA_BASE_FILE_PATH):
        TRACKER_DATA_BASE_DISK_LOCK.acquire()
        with open(TRACKER_DATA_BASE_FILE_PATH, "r") as f:
            json_ser_dict = f.read()
            try:
                data_base_dict = json.loads(json_ser_dict)
            except json.JSONDecodeError:
                data_base_dict = {}
        TRACKER_DATA_BASE_DISK_LOCK.release()
    else:
        data_base_dict = {}
        TRACKER_DATA_BASE_DISK_LOCK.acquire()
        with open(TRACKER_DATA_BASE_FILE_PATH, "w") as f:
            f.write(json.dumps(data_base_dict))
        TRACKER_DATA_BASE_DISK_LOCK.release()

    TRACKER_DATA_BASE_LOCK.acquire()
    TRACKER_DATA_BASE = data_base_dict
    TRACKER_DATA_BASE_LOCK.release()


def Save_Data_Base_To_Disk():
    global TRACKER_DATA_BASE
    global TRACKER_DATA_BASE_LOCK
    global TRACKER_DATA_BASE_DISK_LOCK
    global TRACKER_DATA_BASE_FILE_PATH

    TRACKER_DATA_BASE_LOCK.acquire()
    dict_data_base = TRACKER_DATA_BASE
    TRACKER_DATA_BASE_LOCK.release()

    TRACKER_DATA_BASE_DISK_LOCK.acquire()
    with open(TRACKER_DATA_BASE_FILE_PATH, "w") as f:
        f.write(json.dumps(dict_data_base))

    TRACKER_DATA_BASE_DISK_LOCK.release()


def CleanUp():
    global TRACKER_DATA_BASE
    global TRACKER_DATA_BASE_LOCK
    global PEER_TIMEOUT_THRESHOLD

    TRACKER_DATA_BASE_LOCK.acquire()
    for info_hash in list(TRACKER_DATA_BASE.keys()):
        users = TRACKER_DATA_BASE.get(info_hash)  #users is a list of users
        new_users = Replace_With_New_Users(users, PEER_TIMEOUT_THRESHOLD)
        if new_users:
            TRACKER_DATA_BASE[info_hash] = new_users
        else:
            del TRACKER_DATA_BASE[info_hash]

    TRACKER_DATA_BASE_LOCK.release()


def Replace_With_New_Users(users: list, timeout_time_to_check) -> list:
    new_users = []
    for user in users:
        time_since_last_seen = time.time() - user.get("last_seen")
        if time_since_last_seen < timeout_time_to_check:
            new_users.append(user)

    return new_users


def CleanUp_Thread():
    global CLEAN_UP_THREAD_SLEEP
    while True:
        time.sleep(CLEAN_UP_THREAD_SLEEP)
        CleanUp()


def Save_DB_Thread():
    global SECONDS_TO_SAVE_DATA_BASE
    while True:
        time.sleep(SECONDS_TO_SAVE_DATA_BASE)
        Save_Data_Base_To_Disk()


def Set_Thread_To_Save_DB():
    threading.Thread(target=Save_DB_Thread, daemon=True).start()


def Set_Clean_Up_Thread():
    threading.Thread(target=CleanUp_Thread, daemon=True).start()


if __name__ == "__main__":
    Get_Data_Base_From_Disk()
    #print(TRACKER_DATA_BASE)
    Set_Thread_To_Save_DB()
    Set_Clean_Up_Thread()
    tracker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tracker_sock.bind(("0.0.0.0", LISTEN_PORT))
    tracker_sock.listen(LISTEN_AMOUNT)
    print("tracker listening on port " + str(LISTEN_PORT))
    while True:
        peer_sock, peer_adress = tracker_sock.accept()
        handle_t = threading.Thread(target=handle_peer, args=(peer_sock, peer_adress))
        handle_t.start()
