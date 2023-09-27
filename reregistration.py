# Credit to kasherpete for this code.
import subprocess
import time

def run_command(command):
    try:
        # Start the command as a background subprocess
        process = subprocess.Popen(command, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return process  # Don't wait for the process to complete
        
    except Exception as e:
    
        print(f"Error running the command!")
        return None

if __name__ == "__main__":

    command_to_run = "python3 demo.py --reregister --alive"  # Specify Command (edit as you like)
    interval_minutes = 30

    while True:
        try:
        
            print(f"Reregistering...")
            process = run_command(command_to_run)  # Run command
            
            if process:
                print(f"iMessage number has been reregistered. Waiting for {interval_minutes} minutes.")
                time.sleep(interval_minutes * 60)  # Sleep for the specified interval
                
                process.terminate()  # Terminate the subprocess
                process.wait()  # Wait for the subprocess to finish
                
                print(f"Script terminated.\n")
                
        except KeyboardInterrupt:
        
            print("\n\nScript terminated by user.")
            break