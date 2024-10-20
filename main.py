from app import run_production_server, run_test_server
import os
import dotenv

dotenv.load_dotenv()

if __name__ == '__main__':
    if os.getenv('ENV') == 'PRODUCTION':
        run_production_server()
    elif os.getenv('ENV') == 'TEST':
        run_test_server()
    else:
        print('Invalid environment')