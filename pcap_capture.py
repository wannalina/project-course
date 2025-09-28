import os
import subprocess
import time
from datetime import datetime
import signal

class PCAPManager:
    def __init__(self):
        self.active_captures = {}
        self.capture_metadata = {}


    # function to start packet capture
    def start_capture(self, interface, capture_id=None):
        folder_name = "pcap_traces"
        try:
            # set capture id
            start_time = int(time.time())
            if capture_id is None:
                capture_id = f"capture_{interface}_{start_time}"

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

            # tcpdump in terminal; capture full packets
            cmd = [
                "sudo",
                "tcpdump",
                '-i', 
                f"{interface}",
                "-w",
                f"pcap_traces/{timestamp}.pcap"
            ]
            process = subprocess.Popen(cmd)

            # add metadata
            self.active_captures[capture_id] = process
            self.capture_metadata[capture_id] = {
                'interface': interface,
                'filename': timestamp,
                'filepath': f"{folder_name}/{timestamp}",
                'start_time': datetime.now().isoformat(),
                'status': 'running'
            }

            return capture_id
        except Exception as e:
            print(f"Error starting packet capture: {e}")
            return None


    # function to end packet capture
    def stop_capture(self, capture_id):
        try:
            if capture_id not in self.active_captures:
                print(f"Capture {capture_id} not found")
                return False

            # get process from list and terminate
            process = self.active_captures[capture_id]
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
            
            # update metadata
            self.capture_metadata[capture_id]['end_time'] = datetime.now().isoformat()
            self.capture_metadata[capture_id]['status'] = 'completed'
            
            # remove from active captures list
            del self.active_captures[capture_id]

            return True

        except Exception as e:
            print(f"Error stopping capture ({capture_id}): {e}")
            return False


    # function to stopp all active packet captures
    def stop_all_captures(self):
        capture_ids = list(self.active_captures.keys())
        for capture_id in capture_ids:
            self.stop_capture(capture_id)

    # list current and completed packet captures
    def list_captures(self):
        return {
            'active': list(self.active_captures.keys()),
            'completed': [cid for cid, meta in self.capture_metadata.items() 
                            if meta['status'] == 'completed'],
            'metadata': self.capture_metadata
        }