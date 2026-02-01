from datetime import datetime
from logging import FileHandler, Formatter

TIMESTAMPS = datetime.now().strftime("%Y-%m-%d")
LOG_FILE_NAME = f"{TIMESTAMPS}.quark.log"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(lineno)d]: %(message)s"

defaultFormatter = Formatter(LOG_FORMAT)
defaultHandler = FileHandler(LOG_FILE_NAME, mode="w")
defaultHandler.setFormatter(defaultFormatter)
