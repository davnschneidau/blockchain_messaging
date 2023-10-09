# blockchain_messaging-app

This is a messaging app built in the blockchain. The goal of this app is to use common blockchain techniques of proof of work, encryption, and mining. In order to validate/verify all transactions taking place.

Specifically, users will be able to choose the recveiving address of their messaging and then once verified, that block will be added to the blockchain. 


There are still some tasks to complete...those can be found in the `things_to_add.txt` file.

# running the app

To run the app one must open a terminal window and run the  `blockchain\app.py` then open another deparate terminal window and run the `client\app.py` file. 
If you want to send messages between users you must open two separate instances of `client\app.py` and in one of them change the port in the main function to 5002
```{python}
if __name__ == "__main__":
    app.run(
        host='127.0.0.1',
        port='5002',
        debug='True',
    )
```
