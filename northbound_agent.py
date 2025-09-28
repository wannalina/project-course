import re
from dotenv import load_dotenv
import os
from openai import OpenAI
import requests
from datetime import datetime
import json

from lib.system_prompts import DECISION_SYS_PROMPT
from pcap_capture import PCAPManager


load_dotenv()
API_KEY = os.getenv("API_KEY")
CONTROLLER_URL = os.getenv("CONTROLLER_API_URL")

# init openai client (LLM)
client = OpenAI(api_key=API_KEY)

# get network topology for LLM context
def get_network_topology():
    try: 
        # read topology from json file
        with open('mininet/topology.json', 'r') as f:
            topology = json.load(f)
        return topology
    except Exception as e:
        print(f'Error fetching network topology.json: {e}')
        return None


# get network state for LLM context
def get_network_state():
    try: 
        # get network state from controller
        res = requests.get(f'{CONTROLLER_URL}/intent/get-state')
        network_state = res.json()

        # log in json file
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = f'logs/{timestamp}.json'

        if not os.path.exists('logs'):
            os.mkdir('logs')
        with open (log_filename, 'w') as log_file:
            json.dump(network_state, log_file, indent=2)

        return network_state
    except Exception as e: 
        print(f'Error fetching network state from controller: {e}')
        return None


# parse JSON object 
def parse_json_object(query_output):
    try:
        # extract JSON object from response
        if "```json" in query_output:
            action = query_output.split("```json")[1].split("```")[0]
            return json.loads(action), True

        return None, False
    except Exception as e:
        print(f"Error parsing JSON object: {e}")
        return None, False


# perform LLM query based on given prompt
def perform_query(system_prompt, prompt):
    try: 
        # send query to claude
        response = client.responses.create(
            model="gpt-4o-mini",
            input=[{"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}],
            text={"format": {"type": "text"}},
        )

        # parse response
        full_reply = response.output[0].content[0].text
        print(full_reply)
        return full_reply
    except Exception as e: 
        print(f'Error querying LLM: {e}')
        return None


# build the query to get LLM response
def build_query(user_intent, network_topology, network_state):
    prompt = f"""
        f"# USER INTENT\n{user_intent}\n\n"
        f"# TOPOLOGY (may be null)\n{network_topology}\n\n"
        f"# CONTROLLER STATE (may be null)\n{network_state}\n\n"
        "Return ONLY JSON (no backstory)."
    """

    print("Processing decision query...")
    query_res = perform_query(DECISION_SYS_PROMPT, prompt)

    res, is_json = parse_json_object(query_res)
    return res, is_json


# POST action to controller and implement
def apply_action(action): 
    # post to controller
    res = requests.post(f'{CONTROLLER_URL}/intent/implement', json=action)
    response = res.json()

    # print response in readable format
    print("\n\nController response:\n\n")
    for reply in response.get("results", []):
        print(f"{reply}\n")


# helper function to extract switch interface from pcap
def extract_regex(regex_type, user_intent):
    if regex_type == "interface":
        match = re.search(r"\bs(\d+)-eth(\d+)\b", user_intent, flags=re.IGNORECASE)
    else:
        match = re.search(r"\bcapture_s\d+-eth\d+_\d{9,}\b", user_intent, flags=re.IGNORECASE)

    if not match:
        return None

    return match.group(0) 


# function to handle pcap start/stop/stop all
def handle_pcap_intent(pcap_manager, user_intent):
    try:
        if "Start" in user_intent:
            interface = extract_regex("interface", user_intent)
            capture_id = pcap_manager.start_capture(interface)
            print(f"Packet capture started with ID {capture_id} (Write down)\n")

        elif "Stop capture with ID" in user_intent: 
            capture_id = extract_regex(user_intent)
            pcap_manager.stop_capture(capture_id)
            print(f"Capture with ID {capture_id} stopped successfully.")

        else: 
            pcap_manager.stop_all_captures()

    except Exception as e:
        print(f"Capture operation failed: {e}")


def main():
    action = None
    pcap_manager = PCAPManager()

    while True:
        # get user intent
        user_option = input("Options:\n1 - Start packet capture\n2 - Perform an action\n0 - Exit\n")
        user_option = int(user_option.strip())

        if user_option == 0:
            print("Exiting the intent agent...\n")
            break
        elif user_option == 1:
            user_intent = input("Type one of the following:\n'Start packet capture at s{number}-eth{number}'\n'Stop packet capture at s{number}-eth{number}'\n'Stop all packet captures'\n\n")
            user_intent = user_intent.strip()
            handle_pcap_intent(pcap_manager, user_intent)

        else:
            user_intent = input("Enter the action you would like to implement:\n\n")
            user_intent = user_intent.strip()

            # get context for LLM
            topology = get_network_topology()
            network_state = get_network_state()

            # perform decision query
            action, is_json = build_query(user_intent, topology, network_state)

            # if action in json format, ask permission to execute
            if action and is_json:
                doAction = input("\n\nEnter 'yes' to execute decision (otherwise return to start):\n")

                # if action allowed, save to history and execute
                if doAction.lower() == 'yes':
                    apply_action(action)
                else: 
                    print("No action available or action not needed.")

    # end all pcaps
    pcap_manager.stop_all_captures()

if __name__ == "__main__":
    main()
