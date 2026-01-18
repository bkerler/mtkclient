#!/usr/bin/env python3
import sys

def main():
    if len(sys.argv)<2:
        print("Usage: ./samsung_decode.py \"A055FXXS9CYG2\"")
        sys.exit(1)
    data=sys.argv[1]
    model = data[:-9]
    market = data[-9:-6]
    build = data[-6:-3]
    fwver=data[-3:]

    print(f"Model: {model}")
    print(f"Market: {market}")
    if build[0]=="S":
        print("Security patch")
    elif build[0]=="U":
        print("Update")
    print(f"Bootloader version {build[1]}")
    print(f"OS version {build[2]}")

    yeard=dict(U=2021,V=2022,W=2023,X=2024,Y=2025,Z=2026)
    year=yeard[fwver[0]]
    monthd=dict(A=1,B=2,C=3,D=4,E=5,F=6,G=7,H=8,I=9,J=10,K=11,L=12)
    month=monthd[fwver[1]]
    buildid = fwver[2]
    print(f"{month}/{year} build_id:{buildid}")


if __name__ == "__main__":
    main()