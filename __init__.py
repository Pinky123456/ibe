#python modules
from boneh_chiff import IBEBuilder


def encrypt():
#open file to save parameters gotten
    #through this computation
    builder = IBEBuilder()
    builder.construct_ibe()
    ibe = builder.ibe

    ID = input("Enter the ID you want to use: ")
    print(ID)
    # 加密
    M = input("Enter the message you want to encrypt: ")
    ibe.encrypt(ID, M)


def decrypt():
    builder = IBEBuilder()
    builder.construct_ibe()
    ibe = builder.ibe
    # ibe = IBE()
    # cyphertext = input("Enter the encrypted message, which you want to decrypt: ")
    cypher_texts = ibe.load_cypher_text()
    ID = input("Please enter your ID: ")
    
    count = 0
    for cypher_text in cypher_texts:
        if str(ID) == str(cypher_text['ID']):
            print("————————————")
            print("you have a message!")
            DIDCordX, DIDCordY = ibe.extract(ID)
            ibe.decript(DIDCordX, DIDCordY, cypher_text)
            count = count+1

    if count == 0:
        print("You have no message yet.")


def validate_option(builders):
    try:
        option = input("enter [e]ncrypt or [d]ecrypt: ")
        builder = builders[option]
    except KeyError as e:
        print("sorry, please enter a valid option")
        return (False, None)
    return (True, builder)


if __name__=='__main__':
    builders = dict(e=encrypt, d=decrypt)
    valid_input = False
    while not valid_input:
        valid_input, builder = validate_option(builders)
    builder()