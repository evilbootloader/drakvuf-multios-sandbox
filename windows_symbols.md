```
root@dom0:~# sudo vmi-win-guid domid 52

Windows Kernel found @ 0x100400000
	Version: 64-bit Windows 10
	PE GUID: ba71b4fd1450000
	PDB GUID: 72c69e726c648bc18257af38fa78a2f21
	Kernel filename: ntkrnlmp.pdb
	Multi-processor without PAE
	Signature: 17744.
	Machine: 34404.
	# of sections: 36.
	# of symbols: 0.
	Timestamp: 3128014077.
	Characteristics: 34.
	Optional header size: 240.
	Optional header type: 0x20b
	Section 1: .rdata
	Section 2: .pdata
	Section 3: .idata
	Section 4: .edata
	Section 5: PROTDATA
	Section 6: GFIDS
	Section 7: Pad1
	Section 8: .text
	Section 9: PAGE
	Section 10: PAGELK
	Section 11: POOLCODE
	Section 12: PAGEKD
	Section 13: PAGEVRFY
	Section 14: PAGEHDLS
	Section 15: PAGEBGFX
	Section 16: TRACESUP
	Section 17: PAGECMRC
	Section 18: KVASCODE
	Section 19: KSCP
	Section 20: DRVPRX
	Section 21: fothk
	Section 22: INITKDBG
	Section 23: MINIEX
	Section 24: INIT
	Section 25: Pad2
	Section 26: .data
	Section 27: ALMOSTRO
	Section 28: CACHEALI
	Section 29: PAGEDATA
	Section 30: PAGEVRFD
	Section 31: INITDATA
	Section 32: Pad3
	Section 33: CFGRO
	Section 34: Pad4
	Section 35: .rsrc
	Section 36: .reloc

cd /home/user/drakvuf/volatility3
python3 ./setup.py build
sudo python3 ./setup.py install

python3 /home/user/drakvuf/volatility3/volatility3/framework/symbols/windows/pdbconv.py --guid 72c69e726c648bc18257af38fa78a2f21 -p ntkrnlmp.pdb -o /root/drakvuf-multios-sandbox/profiles/windows.json
```