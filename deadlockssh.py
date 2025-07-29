#!/usr/bin/env python3
"""
DeadlockSSH Server

A full-featured SSH honeypot server that simulates an SSH service to log
connection attempts and analyze potential attackers.

Features:
- Configurable TCP port listening
- Multi-threaded concurrent connections
- Slow SSH banner transmission
- Adaptive delay per client IP
- Comprehensive logging with rotation
- Graceful shutdown handling
- Optional HTTP stats server
- TCP keepalive support

Author: Manus AI Assistant
License: MIT
"""

import socket
import threading
import time
import json
import logging
import logging.handlers
import signal
import sys
import configparser
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, Set, Optional
import argparse
from http_stats_server import HTTPStatsServer


class DeadlockSSH:
    """
    Main SSH Honeypot server class that handles incoming connections,
    implements adaptive delays, and logs all activities.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the SSH honeypot server with configuration.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        # Default configuration
        self.config = {
            'port': 2222,
            'max_connections': 100,
            'ssh_banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
            'banner_delay': 0.1,  # Delay between characters in seconds
            'initial_delay': 1.0,  # Initial delay for new IPs
            'delay_increment': 2.0,  # Delay increment per repeated connection
            'max_delay': 60.0,  # Maximum delay in seconds
            'log_file': 'honeypot.log',
            'log_level': 'INFO',
            'max_log_size': 10 * 1024 * 1024,  # 10MB
            'log_backup_count': 5,
            'max_input_length': 1024,  # Maximum input to log before truncating
            'connection_timeout': 300,  # 5 minutes
            'enable_http_stats': False,
            'http_stats_port': 8080,
            'tcp_keepalive': True
        }
        
        # Load configuration from file if provided
        if config_file:
            self.load_config(config_file)
        
        # Server state
        self.running = False
        self.server_socket = None
        self.active_connections: Set[threading.Thread] = set()
        self.connection_count = 0
        self.ip_delays: Dict[str, float] = defaultdict(lambda: self.config["initial_delay"])
        self.ip_connection_counts: Dict[str, int] = defaultdict(int)
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "connections_per_ip": Counter(),
            "start_time": datetime.now()
        }
        
        self.http_server_thread = None # Initialize HTTP server thread  
        # Setup logging
        self.setup_logging()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.info("DeadlockSSH initialized")
    
    def load_config(self, config_file: str):
        """
        Load configuration from INI file.
        
        Args:
            config_file: Path to configuration file
        """
        try:
            config_parser = configparser.ConfigParser()
            config_parser.read(config_file)
            
            if 'honeypot' in config_parser:
                section = config_parser['honeypot']
                
                # Update configuration with values from file
                self.config['port'] = section.getint('port', self.config['port'])
                self.config['max_connections'] = section.getint('max_connections', self.config['max_connections'])
                self.config['ssh_banner'] = section.get('ssh_banner', self.config['ssh_banner'])
                self.config['banner_delay'] = section.getfloat('banner_delay', self.config['banner_delay'])
                self.config['initial_delay'] = section.getfloat('initial_delay', self.config['initial_delay'])
                self.config['delay_increment'] = section.getfloat('delay_increment', self.config['delay_increment'])
                self.config['max_delay'] = section.getfloat('max_delay', self.config['max_delay'])
                self.config['log_file'] = section.get('log_file', self.config['log_file'])
                self.config['log_level'] = section.get('log_level', self.config['log_level'])
                self.config['max_log_size'] = section.getint('max_log_size', self.config['max_log_size'])
                self.config['log_backup_count'] = section.getint('log_backup_count', self.config['log_backup_count'])
                self.config['max_input_length'] = section.getint('max_input_length', self.config['max_input_length'])
                self.config['connection_timeout'] = section.getint('connection_timeout', self.config['connection_timeout'])
                self.config['enable_http_stats'] = section.getboolean('enable_http_stats', self.config['enable_http_stats'])
                self.config['http_stats_port'] = section.getint('http_stats_port', self.config['http_stats_port'])
                self.config['tcp_keepalive'] = section.getboolean('tcp_keepalive', self.config['tcp_keepalive'])
                
            print(f"Configuration loaded from {config_file}")
            
        except Exception as e:
            print(f"Warning: Could not load configuration file {config_file}: {e}")
            print("Using default configuration")
    
    def setup_logging(self):
        """
        Setup logging with rotation support.
        """
        # Create logger
        self.logger = logging.getLogger("deadlockssh")
        self.logger.setLevel(getattr(logging, self.config['log_level'].upper()))
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            self.config['log_file'],
            maxBytes=self.config['max_log_size'],
            backupCount=self.config['log_backup_count']
        )
        
        # Create console handler
        console_handler = logging.StreamHandler()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def signal_handler(self, signum, frame):
        """
        Handle shutdown signals gracefully.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.shutdown()
    
    def start(self):
        """
        Start the SSH honeypot server.
        """
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Enable TCP keepalive if configured
            if self.config['tcp_keepalive']:
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Bind and listen
            self.server_socket.bind(('0.0.0.0', self.config['port']))
            self.server_socket.listen(self.config['max_connections'])
            
            self.running = True
            self.logger.info(f"DeadlockSSH listening on port {self.config["port"]}")
            
            # Start HTTP stats server if enabled
            if self.config['enable_http_stats']:
                self.start_http_stats_server()
            
            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create and start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    
                    self.active_connections.add(client_thread)
                    client_thread.start()
                    
                    # Clean up finished threads
                    self.cleanup_threads()
                    
                except socket.error as e:
                    if self.running:
                        self.logger.error(f"Socket error: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.shutdown()
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """
        Handle individual client connections.
        
        Args:
            client_socket: Client socket connection
            client_address: Client address tuple (ip, port)
        """
        client_ip = client_address[0]
        
        try:
            # Set socket timeout
            client_socket.settimeout(self.config['connection_timeout'])
            
            # Enable TCP keepalive for client socket if configured
            if self.config['tcp_keepalive']:
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Update statistics
            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1
            self.stats['connections_per_ip'][client_ip] += 1
            self.ip_connection_counts[client_ip] += 1
            
            # Calculate adaptive delay for this IP
            current_delay = min(
                self.ip_delays[client_ip],
                self.config['max_delay']
            )
            
            # Log connection attempt
            self.logger.info(
                f"Connection from {client_ip}:{client_address[1]} "
                f"(attempt #{self.ip_connection_counts[client_ip]}, "
                f"delay: {current_delay:.1f}s)"
            )
            
            # Apply adaptive delay
            if current_delay > 0:
                time.sleep(current_delay)
            
            # Send SSH banner slowly
            self.send_ssh_banner(client_socket)
            
            # Keep connection open and log any data received
            self.monitor_connection(client_socket, client_ip)
            
        except socket.timeout:
            self.logger.info(f"Connection from {client_ip} timed out")
        except ConnectionResetError:
            self.logger.info(f"Connection from {client_ip} reset by peer")
        except Exception as e:
            self.logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            # Update delay for future connections from this IP
            self.ip_delays[client_ip] = min(
                self.ip_delays[client_ip] + self.config['delay_increment'],
                self.config['max_delay']
            )
            
            # Clean up
            try:
                client_socket.close()
            except:
                pass
            
            self.stats['active_connections'] -= 1
            self.logger.info(f"Connection from {client_ip} closed")
    
    def send_ssh_banner(self, client_socket: socket.socket):
        """
        Send SSH banner character by character with delay.
        
        Args:
            client_socket: Client socket to send banner to
        """
        banner = self.config['ssh_banner'] + '\r\n'
        
        for char in banner:
            try:
                client_socket.send(char.encode('utf-8'))
                time.sleep(self.config['banner_delay'])
            except socket.error:
                break
    
    def monitor_connection(self, client_socket: socket.socket, client_ip: str):
        """
        Monitor connection and log any data received from client.
        
        Args:
            client_socket: Client socket to monitor
            client_ip: Client IP address
        """
        buffer = b''
        
        while self.running:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                buffer += data
                
                # Log received data (truncate if too long)
                if len(buffer) > self.config['max_input_length']:
                    log_data = buffer[:self.config['max_input_length']] + b'...[truncated]'
                else:
                    log_data = buffer
                
                # Convert to string for logging, handling non-UTF8 data
                try:
                    log_string = log_data.decode('utf-8', errors='replace')
                except:
                    log_string = repr(log_data)
                
                self.logger.info(f"Data from {client_ip}: {log_string}")
                
                # Reset buffer periodically to prevent memory issues
                if len(buffer) > self.config['max_input_length'] * 2:
                    buffer = buffer[-self.config['max_input_length']:]
                
            except socket.timeout:
                # Continue monitoring on timeout
                continue
            except socket.error:
                break
    
    def cleanup_threads(self):
        """
        Clean up finished threads from active connections set.
        """
        finished_threads = [t for t in self.active_connections if not t.is_alive()]
        for thread in finished_threads:
            self.active_connections.discard(thread)
    
    def start_http_stats_server(self):
        """
        Start HTTP server for statistics.
        """
        if self.config["enable_http_stats"]:
            self.http_server_thread = HTTPStatsServer(
                port=self.config["http_stats_port"],
                stats_ref=self.stats,
                logger=self.logger
            )
            self.http_server_thread.start()
            self.logger.info(f"Attempting to start HTTP stats server on port {self.config['http_stats_port']}")
    
    def shutdown(self):
        """
        Shutdown the server gracefully.
        """
        if not self.running:
            return
            
        self.logger.info("Shutting down DeadlockSSH...")
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Shutdown HTTP stats server if running
        if self.http_server_thread:
            self.http_server_thread.shutdown()
            self.http_server_thread.join(timeout=5) # Wait for thread to finish
            if self.http_server_thread.is_alive():
                self.logger.warning("HTTP stats server thread did not shut down gracefully.")

        # Wait for active connections to finish (with timeout)
        
        start_time = time.time()
        while self.active_connections and (time.time() - start_time) < 10:
            self.cleanup_threads()
            time.sleep(0.1)
        
        # Log final statistics
        uptime = datetime.now() - self.stats['start_time']
        self.logger.info(f"Final statistics:")
        self.logger.info(f"  Total connections: {self.stats['total_connections']}")
        self.logger.info(f"  Uptime: {uptime}")
        self.logger.info(f"  Top attacking IPs: {dict(list(self.stats['connections_per_ip'].most_common(5)))}")
        
        self.logger.info("DeadlockSSH shutdown complete")


def main():
    """
    Main entry point for the DeadlockSSH server.
    """
    parser = argparse.ArgumentParser(description='DeadlockSSH Server')
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default=None
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='Port to listen on (overrides config file)',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        # Create and start honeypot
        honeypot = DeadlockSSH(config_file=args.config)
        
        # Override port if specified via command line
        if args.port:
            honeypot.config['port'] = args.port
        
        honeypot.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

