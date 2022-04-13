import os
from dotenv import load_dotenv
load_dotenv()

# load env vars
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
KID = os.getenv("KID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")

# post processing

if not ACCESS_TOKEN:
    raise ValueError("ACCESS_TOKEN not in Environment Variables")
if not KID:
    raise ValueError("KID not in Environment Variables")
if not PRIVATE_KEY:
    raise ValueError("PRIVATE_KEY not in Environment Variables")
