from pwn import remote


def beginGame(won):
	p = remote("35.242.192.203",30328)
	p.sendline()
	for i in range(3):
		p.recvuntil("dice")
		p.sendline()
	my_score = 0
	your_score = 0
	round = 1
	print("STARTING ROUND", round)

	while(round < 5):
		
		p.recvuntil("I am chosing the ")
		color = p.recvuntil("dice").split()[0].decode()
		#print(color)
		if (round == 1):
			if color == "red":
				p.sendline("yellow")
			else:
				p.sendline("red")
		elif (round == 2 or round == 4):
			if color == "red":
				p.sendline("blue")
			else:
				p.sendline("red")

		elif (round == 3):
			if color == "green":
				p.sendline("yellow")
			else:
				p.sendline("green")
		p.recvuntil("Your number")
		score = p.recvuntil("win").split()[-2].decode()
		if(score == "You"):
			my_score += 1
		else:
			your_score += 1
		#print("Score: Player:",my_score,"vs Comp: ",your_score)
		if my_score + your_score == 101:
			if my_score < your_score:
				print("MISSION FAILED, WE'LL GET 'EM NEXT TIME")
				print("TRYING AGAIN")
				return False
			else:
				my_score = 0
				your_score = 0
				round += 1
				if round == 5:
					p.recvuntil("rounds!")
					flag = p.recvuntil("}").decode()
					print(flag)
					return True
				print("STARTING ROUND", round)
				if (round == 3):
					for i in range(4):
						p.sendline()

won = False
while not won:
	won = beginGame(won)
