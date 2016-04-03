#!/usr/bin/env python

# Project Euler solutions (https://projecteuler.net)
def main():
    current()

def current():
    all_lines = [
        [8,2,22,97,38,15,0,40,0,75,04,5,7,78,52,12,50,77,91,8],
        [49,49,99,40,17,81,18,57,60,87,17,40,98,43,69,48,4,56,62,0],
        [81,49,31,73,55,79,14,29,93,71,40,67,53,88,30,3,49,13,36,65],
        [52,70,95,23,4,60,11,42,69,24,68,56,1,32,56,71,37,2,36,91],
        [22,31,16,71,51,67,63,89,41,92,36,54,22,40,40,28,66,33,13,80],
        [24,47,32,60,99,3,45,2,44,75,33,53,78,36,84,20,35,17,12,50],
        [32,98,81,28,64,23,67,10,26,38,40,67,59,54,70,66,18,38,64,70],
        [67,26,20,68,2,62,12,20,95,63,94,39,63,8,40,91,66,49,94,21],
        [24,55,58,5,66,73,99,26,97,17,78,78,96,83,14,88,34,89,63,72],
        [21,36,23,9,75,0,76,44,20,45,35,14,0,61,33,97,34,31,33,95],
        [78,17,53,28,22,75,31,67,15,94,03,80,4,62,16,14,9,53,56,92],
        [16,39,5,42,96,35,31,47,55,58,88,24,0,17,54,24,36,29,85,57],
        [86,56,0,48,35,71,89,7,5,44,44,37,44,60,21,58,51,54,17,58],
        [19,80,81,68,5,94,47,69,28,73,92,13,86,52,17,77,4,89,55,40],
        [4,52,8,83,97,35,99,16,7,97,57,32,16,26,26,79,33,27,98,66],
        [88,36,68,87,57,62,20,72,03,46,33,67,46,55,12,32,63,93,53,69],
        [4,42,16,73,38,25,39,11,24,94,72,18,8,46,29,32,40,62,76,36],
        [20,69,36,41,72,30,23,88,34,62,99,69,82,67,59,85,74,4,36,16],
        [20,73,35,29,78,31,90,1,74,31,49,71,48,86,81,16,23,57,5,54],
        [1,70,54,71,83,51,54,69,16,92,33,48,61,43,52,1,89,19,67,48],
    ]
    greatest_product = 0
    
    for i,line in enumerate(all_lines):

        
        all_lines[i] * all_lines[i+1]

        print all_lines[i],all_lines[i-1]


def ten(): #142913828922
        def is_prime(n):
            if n <= 3:
                return n >= 2
            if n % 2 == 0 or n % 3 == 0:
                return False
            for i in xrange(5, int(n ** 0.5) + 1, 6):
                if n % i == 0 or n % (i + 2) == 0:
                    return False
            return True
        i=0
        total = 0
        while i < 2000001:
            if is_prime(i): total+=i
            i+=1
        print total


def nine(): #31875000
    i,j,k=0,0,0
    sum_asked = 1000
    for i in xrange(1,1000):
        for j in xrange(i+1,1000):
            for k in xrange(j+1,1000):
                if i+j+k == sum_asked:
                    if i**2 + j**2 == k**2:
                        print str(i),str(j),str(k)
                        print i*j*k
                        return
        pass


def eight(): #23514624000
    big_number = "73167176531330624919225119674426574742355349194934"
    big_number += "96983520312774506326239578318016984801869478851843"
    big_number += "85861560789112949495459501737958331952853208805511"
    big_number += "12540698747158523863050715693290963295227443043557"
    big_number += "66896648950445244523161731856403098711121722383113"
    big_number += "62229893423380308135336276614282806444486645238749"
    big_number += "30358907296290491560440772390713810515859307960866"
    big_number += "70172427121883998797908792274921901699720888093776"
    big_number += "65727333001053367881220235421809751254540594752243"
    big_number += "52584907711670556013604839586446706324415722155397"
    big_number += "53697817977846174064955149290862569321978468622482"
    big_number += "83972241375657056057490261407972968652414535100474"
    big_number += "82166370484403199890008895243450658541227588666881"
    big_number += "16427171479924442928230863465674813919123162824586"
    big_number += "17866458359124566529476545682848912883142607690042"
    big_number += "24219022671055626321111109370544217506941658960408"
    big_number += "07198403850962455444362981230987879927244284909188"
    big_number += "84580156166097919133875499200524063689912560717606"
    big_number += "05886116467109405077541002256983155200055935729725"
    big_number += "71636269561882670428252483600823257530420752963450"

    greatest_product = 0
    adjacent_digits = ''
    for i in xrange(13,len(big_number)+1):
        sequence = big_number[(i-13):i]
        product =  reduce(lambda x, y: x*y, [ int(i) for i in sequence ])
        if product > greatest_product: 
            greatest_product = product
            adjacent_digits = sequence

    print greatest_product

def seven(): #104743
    def is_prime(n):
        if n <= 3:
            return n >= 2
        if n % 2 == 0 or n % 3 == 0:
            return False
        for i in xrange(5, int(n ** 0.5) + 1, 6):
            if n % i == 0 or n % (i + 2) == 0:
                return False
        return True
    
    counter,last_prime = 0,0
    i=2
    while counter < 10001:
        if is_prime(i):
            counter +=1
            last_prime = i
        i+=1

    print last_prime
        
def six(): #25164150
    i = sum([ a**2 for a in range(101)])
    j = sum(range(101))**2
    print j-i

def five(): #232792560
    i=20
    while i<=1000000000:
        j=20 
        failed_answer = False
        while j>1 and not failed_answer:
            if i % j != 0: 
                failed_answer = True
                break
            j-=1
        if not failed_answer:
            print i
            return    
        i+=1

def four(): #906609
    i,j = 999,999
    result = 0
    while i>1:
        while j>1:
            k = i*j
            if str(k) == str(k)[::-1]:
                print k
                result=k if k>result else result
            j-=1
        i-=1
        j=999
    print result
    
def three(): #6857
    number = 600851475143
    last_prime_factor = 2
    i = 2
    while i <= (number):
        if number % i == 0: 
            last_prime_factor = i
            number = number/i #reduce number
            i=2 #reset i
        else:
            i+=1
    print last_prime_factor

def two():
    a,b,result = 1,2,2
    while b < 4000000:
        a,b = b,a+b
        result = (result+b) if (b % 2 == 0) else result
    print result

def one():
    print sum([ a for a in range(1000) if (a%3==0) or (a%5==0) ])

if __name__ == '__main__':
    main()
