from app.model.scanner import handler as scanner
from app.model.health_check import handler as health_check
from app.util import handler_util as base
from app.util.config_util import config


ROUTERS = [
    (r"/", scanner.ScannerHandler),
    (r"/ping", health_check.HealthCheckHandler),
    (r"/(.*\..*)", base.StaticHandler, {"path": config.static_path}),
    (r".*", base.PageNotFoundHandler),
]
