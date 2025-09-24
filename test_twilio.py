try: 
    from twilio.rest import Client
    print("Twilio imported succesfully!")
except ImportError as e:
    print(f"Import error:{e}")
        