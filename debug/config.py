import logging
import time
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] %(message)s %(funcName)20s() - %(filename)s', 
                    datefmt='%d-%m-%Y %H:%M:%S', filename=f"var/osssec/logs/{time.strftime('%Y-%m-%d')}.log")

