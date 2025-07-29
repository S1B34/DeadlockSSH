import http.server
import socketserver
import json
import threading
from datetime import datetime

class HTTPStatsServer(threading.Thread):
    """
    A simple HTTP server to expose honeypot statistics.
    """
    def __init__(self, port: int, stats_ref: dict, logger):
        super().__init__()
        self.port = port
        self.stats_ref = stats_ref  # Reference to the honeypot's stats dictionary
        self.logger = logger
        self.httpd = None
        self.daemon = True  # Allow the main program to exit even if this thread is running

    def run(self):
        Handler = self._create_handler()
        try:
            self.httpd = socketserver.TCPServer(("0.0.0.0", self.port), Handler)
            self.logger.info(f"HTTP Stats Server listening on port {self.port}")
            self.httpd.serve_forever()
        except Exception as e:
            self.logger.error(f"Failed to start HTTP Stats Server: {e}")

    def _create_handler(self):
        # Capture self.stats_ref in the closure
        _stats_ref = self.stats_ref
        _logger = self.logger

        class StatsHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/stats":
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    
                    # Prepare stats for JSON serialization
                    current_stats = _stats_ref.copy()
                    current_stats["start_time"] = current_stats["start_time"].isoformat()
                    current_stats["connections_per_ip"] = dict(current_stats["connections_per_ip"])

                    self.wfile.write(json.dumps(current_stats, indent=4).encode("utf-8"))
                    _logger.info(f"HTTP Stats request from {self.client_address[0]}: /stats")
                else:
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<h1>404 Not Found</h1>")
                    _logger.warning(f"HTTP Stats request from {self.client_address[0]}: {self.path} (404)")

        return StatsHandler

    def shutdown(self):
        if self.httpd:
            self.logger.info("Shutting down HTTP Stats Server...")
            self.httpd.shutdown()
            self.httpd.server_close()



