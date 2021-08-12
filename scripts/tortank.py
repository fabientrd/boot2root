import turtle
import re

tortank = turtle.Turtle()

def find_int(myline):
    return int(re.search(r'\d+', myline).group())

myfile = open("turtle.txt", "r")
myline = myfile.readline()
while myline:
    if "Tourne" in myline:
        if "gauche" in myline:
            tortank.left(find_int(myline))
        elif "droite" in myline:
            tortank.right(find_int(myline))
    elif "Avance" in myline:
        tortank.forward(find_int(myline))
    elif "Recule" in myline:
        tortank.backward(find_int(myline))
    else:
        tortank.clear()
    myline = myfile.readline()
myfile.close()
