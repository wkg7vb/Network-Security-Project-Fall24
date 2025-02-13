from hashlib import sha1
from itertools import permutations
from multiprocessing import Process


def checkPW(pw, passwords):
    hashedpw = sha1(pw.encode('utf-8')).hexdigest()
    for user in passwords:
        if hashedpw == passwords[user]:
            print(f'User {user}\'s password cracked: Reverse hash of {hashedpw} is {pw}')
            break


# check nums
def checkNums(npws, startnum, endnum):
    for num in range(startnum, endnum):
        checkPW(str(num), npws)


def checkPNums(pnpws, startnum, endnum, width):
    for pnum in range(startnum, endnum):
        for length in range(width + 1):
            if length > len(str(pnum)):
                checkPW(str(pnum).zfill(length), pnpws)


# check single words
def checkSW(swpws, singlewords):
    for word in singlewords:
        checkPW(word, swpws)


def checkSWNums(swnpws, singlewords, startnum, endnum):
    for word in singlewords:
        for num in range(startnum, endnum):
            checkPW(word + str(num), swnpws)


def checkSWPNums(swpnpws, singlewords, startnum, endnum, width):
    for word in singlewords:
        for pnum in range(startnum, endnum):
            for length in range(width + 1):
                if length > len(str(pnum)):
                    checkPW(word + str(pnum).zfill(length), swpnpws)


# check double words
def checkDW(dwpws, doublewords):
    for dword in doublewords:
        checkPW(''.join(dword), dwpws)


def checkDWNums(dwnpws, doublewords, startnum, endnum):
    for dword in doublewords:
        for num in range(startnum, endnum):
            checkPW(''.join(dword) + str(num), dwnpws)


def checkDWPNums(dwpnpws, doublewords, startnum, endnum, width):
    for dword in doublewords:
        for pnum in range(startnum, endnum):
            for length in range(width + 1):
                if length > len(str(pnum)):
                    checkPW(''.join(dword) + str(pnum).zfill(length), dwpnpws)


# check triple words
def checkTW(twpws, singlewords, doublewords):
    for word in singlewords:
        for dword in doublewords:
            if word not in dword:
                checkPW(word + ''.join(dword), twpws)


def checkTWNums(twnpws, singlewords, doublewords, startnum, endnum):
    for word in singlewords:
        for dword in doublewords:
            if word not in dword:
                for num in range(startnum, endnum):
                    checkPW(word + ''.join(dword) + str(num), twnpws)


def checkTWPNums(twpnpws, singlewords, doublewords, startnum, endnum, width):
    for word in singlewords:
        for dword in doublewords:
            if word not in dword:
                for pnum in range(startnum, endnum):
                    for length in range(width + 1):
                        if length > len(str(pnum)):
                            checkPW(word + ''.join(dword) + str(pnum).zfill(length), twpnpws)


def createProcesses():
    # nums processes
    numsP = [
        Process(target=checkNums, args=(pwtocrack, 0, 1000000000)),
        Process(target=checkNums, args=(pwtocrack, 1000000000, 2000000000)),
        Process(target=checkNums, args=(pwtocrack, 2000000000, 3000000000)),
        Process(target=checkNums, args=(pwtocrack, 3000000000, 4000000000)),
        Process(target=checkNums, args=(pwtocrack, 4000000000, 5000000000)),
        Process(target=checkNums, args=(pwtocrack, 5000000000, 6000000000)),
        Process(target=checkNums, args=(pwtocrack, 6000000000, 7000000000)),
        Process(target=checkNums, args=(pwtocrack, 7000000000, 8000000000)),
        Process(target=checkNums, args=(pwtocrack, 8000000000, 9000000000)),
        Process(target=checkNums, args=(pwtocrack, 9000000000, 10000000000))]
    pnumsP = [
        Process(target=checkPNums, args=(pwtocrack, 0, 1000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 1000000000, 2000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 2000000000, 3000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 3000000000, 4000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 4000000000, 5000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 5000000000, 6000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 6000000000, 7000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 7000000000, 8000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 8000000000, 9000000000, 10)),
        Process(target=checkPNums, args=(pwtocrack, 9000000000, 10000000000, 10))]

    # single word processes
    swP = [
        Process(target=checkSW, args=(pwtocrack, singlewords[:558])),
        Process(target=checkSW, args=(pwtocrack, singlewords[558:1116])),
        Process(target=checkSW, args=(pwtocrack, singlewords[1116:1674])),
        Process(target=checkSW, args=(pwtocrack, singlewords[1674:2232])),
        Process(target=checkSW, args=(pwtocrack, singlewords[2232:2790])),
        Process(target=checkSW, args=(pwtocrack, singlewords[2790:3348])),
        Process(target=checkSW, args=(pwtocrack, singlewords[3348:3906])),
        Process(target=checkSW, args=(pwtocrack, singlewords[3906:4464])),
        Process(target=checkSW, args=(pwtocrack, singlewords[4464:5022])),
        Process(target=checkSW, args=(pwtocrack, singlewords[5022:]))]
    swnumsP = [
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 0, 10000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 10000, 20000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 20000, 30000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 30000, 40000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 40000, 50000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 50000, 60000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 60000, 70000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 70000, 80000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 80000, 90000)),
        Process(target=checkSWNums, args=(pwtocrack, singlewords, 90000, 100000))]
    swpnumsP = [
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 0, 1000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 1000, 2000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 2000, 3000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 3000, 4000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 4000, 5000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 5000, 6000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 6000, 7000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 7000, 8000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 8000, 9000, 5)),
        Process(target=checkSWPNums, args=(pwtocrack, singlewords, 9000, 10000, 5))]

    # double word processes FIXME add more process groups for dwpnums
    dwP = [
        Process(target=checkDW, args=(pwtocrack, doublewords[:3111966])),
        Process(target=checkDW, args=(pwtocrack, doublewords[3111966:6223932])),
        Process(target=checkDW, args=(pwtocrack, doublewords[6223932:9335898])),
        Process(target=checkDW, args=(pwtocrack, doublewords[9335898:12447864])),
        Process(target=checkDW, args=(pwtocrack, doublewords[12447864:15559830])),
        Process(target=checkDW, args=(pwtocrack, doublewords[15559830:18671796])),
        Process(target=checkDW, args=(pwtocrack, doublewords[18671796:21783762])),
        Process(target=checkDW, args=(pwtocrack, doublewords[21783762:24895728])),
        Process(target=checkDW, args=(pwtocrack, doublewords[24895728:28007694])),
        Process(target=checkDW, args=(pwtocrack, doublewords[28007694:]))]
    dwnums0P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[:3111966], 900, 1000))]
    dwnums1P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[3111966:6223932], 900, 1000))]
    dwnums2P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[6223932:9335898], 900, 1000))]
    dwnums3P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[9335898:12447864], 900, 1000))]
    dwnums4P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[12447864:15559830], 900, 1000))]
    dwnums5P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[15559830:18671796], 900, 1000))]
    dwnums6P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[18671796:21783762], 900, 1000))]
    dwnums7P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[21783762:24895728], 900, 1000))]
    dwnums8P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[24895728:28007694], 900, 1000))]
    dwnums9P = [
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 0, 100)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 100, 200)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 200, 300)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 300, 400)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 400, 500)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 500, 600)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 600, 700)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 700, 800)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 800, 900)),
        Process(target=checkDWNums, args=(pwtocrack, doublewords[28007694:], 900, 1000))]
    dwpnumsP = [
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 0, 1000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 1000, 2000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 2000, 3000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 3000, 4000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 4000, 5000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 5000, 6000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 6000, 7000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 7000, 8000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 8000, 9000, 5)),
        Process(target=checkDWPNums, args=(pwtocrack, doublewords, 9000, 10000, 5))]

    # triple word processes
    twP = [
        Process(target=checkTW, args=(pwtocrack, singlewords[:558], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[558:1116], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[1116:1674], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[1674:2232], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[2232:2790], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[2790:3348], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[3348:3906], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[3906:4464], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[4464:5022], doublewords)),
        Process(target=checkTW, args=(pwtocrack, singlewords[5022:], doublewords))]
    twnums0P = [
        Process(target=checkTWNums, args=(pwtocrack, singlewords[:558], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 0, 10)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 0, 10))]
    twnums1P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[558:1116], doublewords, 90000, 100000))]
    twnums2P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 90000, 100000))]
    twnums3P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 90000, 100000))]
    twnums4P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 90000, 100000))]
    twnums5P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 90000, 100000))]
    twnums6P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 90000, 100000))]
    twnums7P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 90000, 100000))]
    twnums8P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 90000, 100000))]
    twnums9P = [

        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 10000, 20000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 20000, 30000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 30000, 40000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 40000, 50000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 50000, 60000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 60000, 70000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 70000, 80000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 80000, 90000)),
        Process(target=checkTWNums, args=(pwtocrack, singlewords[5022:], doublewords, 90000, 100000))]
    twpnums0P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[:558], doublewords, 90000, 100000, 5))]
    twpnums1P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[558:1116], doublewords, 90000, 100000, 5))]
    twpnums2P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1116:1674], doublewords, 90000, 100000, 5))]
    twpnums3P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[1674:2232], doublewords, 90000, 100000, 5))]
    twpnums4P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2232:2790], doublewords, 90000, 100000, 5))]
    twpnums5P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[2790:3348], doublewords, 90000, 100000, 5))]
    twpnums6P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3348:3906], doublewords, 90000, 100000, 5))]
    twpnums7P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[3906:4464], doublewords, 90000, 100000, 5))]
    twpnums8P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[4464:5022], doublewords, 90000, 100000, 5))]
    twpnums9P = [
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 0, 10000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 10000, 20000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 20000, 30000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 30000, 40000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 40000, 50000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 50000, 60000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 60000, 70000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 70000, 80000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 80000, 90000, 5)),
        Process(target=checkTWPNums, args=(pwtocrack, singlewords[5022:], doublewords, 90000, 100000, 5))]

    completedgroups = []

    processgroups = [numsP, pnumsP,
                       swP, swnumsP, swpnumsP,
                       dwP, dwnums0P, dwnums1P, dwnums2P, dwnums3P, dwnums4P, dwnums5P, dwnums6P, dwnums7P, dwnums8P,
                       dwnums9P,
                       dwpnumsP, twP,
                       twnums0P, twnums1P, twnums2P, twnums3P, twnums4P, twnums5P, twnums6P, twnums7P, twnums8P, twnums9P,
                       twpnums0P, twpnums1P, twpnums2P, twpnums3P, twpnums4P, twpnums5P, twpnums6P, twpnums7P, twpnums8P,
                       twpnums9P]

    return processgroups


if __name__ == '__main__':

    pwtocrack = {}
    notfoundpws = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    with open('passwords.txt', 'r', encoding='utf-8-sig') as pwfile:
        for index, line in enumerate(pwfile):
            if index + 1 in notfoundpws:
                pwtocrack[line[:3].strip()] = line[3:].strip()

    with open('dictionary.txt', 'r', encoding='utf-8-sig') as dictfile:
        singlewords = [line.strip() for line in dictfile]

    doublewords = []
    for dword in permutations(singlewords, 2):
        doublewords.append(''.join(dword))
    print('doublewords built')

    for group in createProcesses():
        for process in group:
            process.start()

        for process in group:
            process.join()

        print(f'{group} completed')

    print('all process groups completed')