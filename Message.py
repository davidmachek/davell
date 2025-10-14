import time
from colorama import Fore
def info(msg):
    print(f" ** <{time.strftime("%H:%M:%S")}> [{Fore.BLUE}inf{Fore.RESET}] {msg}")
def error(msg):
    print(f" ** <{time.strftime("%H:%M:%S")}> [{Fore.RED}err{Fore.RESET}] {msg}")
def warning(msg):
    print(f" ** <{time.strftime("%H:%M:%S")}> [{Fore.YELLOW}war{Fore.RESET}] {msg}")
def own(title,msg):
    print(f" ** <{time.strftime("%H:%M:%S")}> [{Fore.GREEN}{title[:3].lower()}{Fore.RESET}] {msg}")