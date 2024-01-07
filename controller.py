#!/usr/bin/python3
import os
import pyfiglet
from core.colors import *
from modules.web.web_controller import *
#from modules.network.net_controller import *




if __name__ == '__main__':
    
    def banner():
        result = pyfiglet.figlet_format("VAPT Tool") 
        print(result) 
        
    def menu():
        print('\n')
        print(f"{green}[1] Web")
        print(f"{green}[2] Network")
        choice = input("Enter your choice: ")
        return choice
        
    def main():
        try:
            banner()
            choice = menu()
            if choice == "1":
                choice = web_menu()
                runWeb(choice)
            elif choice == "2":
                # choice = network_menu()
                # runNet(choice)
                pass
                
            else:
                print(f"\n\n{red}Invalid Choice! Try Again.\n")
        except KeyboardInterrupt:
            print(f"\n{red}[!]Program Exit By user")
            exit(0)
        except Exception as e:
            print(f"{bad}An error occurred: {str(e)}")
            exit(1)       
            
    main()