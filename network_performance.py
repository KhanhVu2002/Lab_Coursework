import json
import subprocess
import platform
import time
import os
import configparser
import re
import logging
import csv
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import signal


def visualize_network_data(csv_file):
    """Visualize the network performance data from the CSV file"""
    df = pd.read_csv(csv_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Plot download and upload speeds
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(df['timestamp'], df['download_speed'], label='Download Speed')
    ax.plot(df['timestamp'], df['upload_speed'], label='Upload Speed')
    ax.set_title('Network Speeds')
    ax.set_xlabel('Time')
    ax.set_ylabel('Speed (Mbps)')
    ax.legend()
    plt.tight_layout()
    plt.show(block=False)
    input("Press Enter to close the download/upload speed plot...")
    plt.close()

    # Plot latency
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(df['timestamp'], df['latency'])
    ax.set_title('Latency')
    ax.set_xlabel('Time')
    ax.set_ylabel('Latency (ms)')
    plt.tight_layout()
    plt.show(block=False)
    input("Press Enter to close the latency plot...")
    plt.close()

    # Plot Wi-Fi signal strength
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(df['timestamp'], df['wifi_rssi'])
    ax.set_title('Wi-Fi Signal Strength')
    ax.set_xlabel('Time')
    ax.set_ylabel('RSSI (dBm)')
    plt.tight_layout()
    plt.show(block=False)
    input("Press Enter to close the Wi-Fi signal strength plot...")
    plt.close()


def setup_logging():
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f'network_performance_{time.strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=log_file,
        filemode='w'
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    logging.info('Logging initialized')
    return log_file

def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

def run_speedtest():
    config = load_config()
    try:
        output = subprocess.check_output([config.get('Paths', 'speedtest_exe'), '-f', 'json'])
        speedtest_result = json.loads(output.decode('utf-8'))
        return speedtest_result
    except FileNotFoundError:
        logging.error(f"Speedtest executable not found at: {config.get('Paths', 'speedtest_exe')}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run speedtest: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error while running speedtest: {e}")
        return None

def parse_wifi_networks(output):
    """Parse Wi-Fi networks output from netsh command"""
    networks = []
    for network_block in output.split('\n\n'):
        ssid_match = re.search(r'SSID \d+ : (.+)', network_block)
        if ssid_match:
            ssid = ssid_match.group(1)
            signal_match = re.search(r'Signal\s+: (\d+)%', network_block)
            signal = int(signal_match.group(1)) if signal_match else None
            security_match = re.search(r'Authentication\s+: (.+)', network_block)
            security = security_match.group(1) if security_match else None
            networks.append({
                'wifi_ssid': ssid,
                'wifi_rssi': signal,
                'wifi_standard': 'Unknown',
                'wifi_security': security
            })
    return networks

def scan_wifi_networks(interface='wlan0'):
    try:
        result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], universal_newlines=True)
        return parse_wifi_networks(result)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning for Wi-Fi networks: {e}")
        return None

def ping_host(host, timeout=5):
    """
    Ping a host and return the average latency.
    
    Args:
        host (str): The host to ping.
        timeout (int): The timeout for the ping command in seconds.
    
    Returns:
        float: The average latency in milliseconds, or None if the ping fails.
    """
    try:
        logging.info(f"Pinging host: {host}")
        if platform.system() == 'Windows':
            output = subprocess.check_output(['ping', '-n', '4', host], universal_newlines=True, timeout=timeout)
        else:
            output = subprocess.check_output(['ping', '-c', '4', host], universal_newlines=True, timeout=timeout)
        logging.info(f"Ping output:\n{output}")
        
        if platform.system() == 'Windows':
            latency_match = re.search(r'Average = (\d+)ms', output)
        else:
            latency_match = re.search(r'avg = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms', output)
        
        if latency_match:
            if platform.system() == 'Windows':
                avg_latency = float(latency_match.group(1))
            else:
                avg_latency = float(latency_match.group(1))
            logging.info(f"Latency to {host}: Avg={avg_latency:.2f} ms")
            return avg_latency
        else:
            logging.warning(f"No latency information found in ping output for host {host}")
            return None
    except subprocess.TimeoutExpired:
        logging.error(f"Ping to {host} timed out after {timeout} seconds")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error pinging host {host}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Error parsing ping output for host {host}: {e}")
        return None

def capture_packets(interface, duration):
    """Capture network packets using Wireshark and save the capture file"""
    config = load_config()
    try:
        capture_file = f'capture_{time.strftime("%Y%m%d_%H%M%S")}.pcapng'
        wireshark_process = subprocess.Popen([config.get('Paths', 'wireshark_exe'), '-i', interface, '-a', f'duration:{duration}', '-w', capture_file])
        logging.info(f'Network packet capture started. Waiting for {duration} seconds...')

        # Wait for the specified duration or until the Wireshark process terminates
        try:
            wireshark_process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            # Terminate the Wireshark process if it's still running
            logging.info('Stopping Wireshark capture...')
            wireshark_process.terminate()
            try:
                wireshark_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logging.warning('Wireshark capture did not stop gracefully, sending SIGINT...')
                os.kill(wireshark_process.pid, signal.SIGINT)

        logging.info(f'Network packet capture saved to: {os.path.abspath(capture_file)}')
        return capture_file
    except subprocess.CalledProcessError as e:
        logging.error(f'Failed to capture network packets: {e}')
        return None
    except OSError as e:
        logging.error(f'Error running Wireshark: {e}')
        return None
    except FileNotFoundError:
        logging.error(f'Wireshark executable not found at: {config.get("Paths", "wireshark_exe")}')
        return None
    except Exception as e:
        logging.error(f'Unexpected error while capturing network packets: {e}')
        return None

def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config


def save_data_to_csv(data):
    csv_file = 'network_performance_data.csv'
    with open(csv_file, 'a', newline='') as csvfile:
        fieldnames = ['timestamp', 'download_speed', 'upload_speed', 'latency', 'wifi_ssid', 'wifi_rssi', 'wifi_standard', 'wifi_security']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if os.path.getsize(csv_file) == 0:
            writer.writeheader()

        writer.writerow(data)

    return csv_file

def main():
    parser = argparse.ArgumentParser(description='Network performance measurement script')
    parser.add_argument('--duration', type=int, default=60, help='Duration to run the script in seconds')
    parser.add_argument('--interface', type=str, default='wlan0', help='Network interface to use')
    args = parser.parse_args()

    log_file = setup_logging()
    logging.info('Starting network performance measurement')

    start_time = time.time()
    timeout = args.duration

    while time.time() - start_time < timeout:
        speedtest_result = run_speedtest()
        if speedtest_result:
            download_speed = speedtest_result.get('download', {}).get('bandwidth', 0)
            upload_speed = speedtest_result.get('upload', {}).get('bandwidth', 0)
            logging.info(f"Download speed: {download_speed / 1e6:.2f} Mbps")
            logging.info(f"Upload speed: {upload_speed / 1e6:.2f} Mbps")

        wifi_networks = scan_wifi_networks(args.interface)
        wifi_network_info = []
        if wifi_networks:
            for network in wifi_networks:
                wifi_network_info.append(network)
                logging.info(f"SSID: {network['wifi_ssid']}")
                logging.info(f"RSSI: {network['wifi_rssi']} dBm")
                logging.info(f"Security: {network['wifi_security']}")
                logging.info("---")

        host = 'www.example.com'
        latency = ping_host(host)
        if latency is not None:
            logging.info(f"Latency to {host}: {latency:.2f} ms")

        capture_file = capture_packets(args.interface, timeout)
        if capture_file:
            logging.info(f"Network packet capture saved to: {capture_file}")

        data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'download_speed': download_speed / 1e6 if speedtest_result else 0,
            'upload_speed': upload_speed / 1e6 if speedtest_result else 0,
            'latency': latency if latency is not None else 0,
            'wifi_ssid': wifi_network_info[0]['wifi_ssid'] if wifi_network_info else '',
            'wifi_rssi': wifi_network_info[0]['wifi_rssi'] if wifi_network_info else 0,
            'wifi_standard': wifi_network_info[0]['wifi_standard'] if wifi_network_info else '',
            'wifi_security': wifi_network_info[0]['wifi_security'] if wifi_network_info else ''
        }
        csv_file = save_data_to_csv(data)
        visualize_network_data(csv_file)
        logging.info(f"Network performance data saved to: {csv_file}")

        time.sleep(10)  # Wait for 10 seconds before the next iteration

if __name__ == '__main__':
    main()
