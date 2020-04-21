## S-DES Simplified Data Encryption Standard 
txtCipher=IP-1(fK2(P(fK1(IP(txtInput)))))
```bash
function encryption {
txtInput=($1); shift
keyInput=($1)
key1=($(keyGeneration1 "${keyInput[*]}")) #KeyGen 1
key2=($(keyGeneration2 "${keyInput[*]}")) #KeyGen 2
txtIp=($(permutation "${ip[*]}" "${txtInput[*]}")) #Ip
txtRound=($(round "${txtIp[*]}" "${key1[*]}")) #fK1
txtRoundRotate=(${txtRound[@]:4:8}); txtRoundRotate+=(${txtRound[@]:0:4}) #P
txtRound=($(round "${txtRoundRotate[*]}" "${key2[*]}")) #fK2
echo $(permutation "${ip1[*]}" "${txtRound[*]}") #Ip-1
}
```
txtDecrypted=IP-1(fK1(P(fK2(IP(ciphertext)))))
```bash
function decryption {
txtInput=($1); shift
keyInput=($1)
key1=($(keyGeneration1 "${keyInput[*]}")) #KeyGen 1
key2=($(keyGeneration2 "${keyInput[*]}")) #KeyGen 2
txtIp=($(permutation "${ip[*]}" "${txtInput[*]}")) #Ip
txtRound=($(round "${txtIp[*]}" "${key2[*]}")) #fK1
txtRoundRotate=(${txtRound[@]:4:8}); txtRoundRotate+=(${txtRound[@]:0:4}) #P
txtRound=($(round "${txtRoundRotate[*]}" "${key1[*]}")) #fK2
echo $(permutation "${ip1[*]}" "${txtRound[*]}") #Ip-1
}
```
key1=P8(Offset(P10(keyIn)))
```bash
function keyGeneration1 {
keyIn=($1)
keyP10=($(permutation "${p10[*]}" "${keyIn[*]}")) #p10
keyL=(${keyP10[@]:0:5}); keyR=(${keyP10[@]:5:10}) #Division
ls1L=(${keyL[@]:1:4}); ls1R+=(${keyR[@]:1:4}) #Offset <
ls1L[5]=${keyL[0]}; ls1R[5]=${keyR[0]}
ls1=(${ls1L[@]}); ls1+=(${ls1R[@]})
echo $(permutation "${p8[*]}" "${ls1[*]}") #p8
}
```
key2=P8(Offset(Offset(P10(keyIn))))
```bash
function keyGeneration2 {
keyIn=($1)
keyP10=($(permutation "${p10[*]}" "${keyIn[*]}")) #p10
keyL=(${keyP10[@]:0:5}); keyR=(${keyP10[@]:5:10}) #Division
ls1L=(${keyL[@]:1:4}); ls1R+=(${keyR[@]:1:4}) #Offset <
ls1L[5]=${keyL[0]}; ls1R[5]=${keyR[0]}
ls1=(${ls1L[@]}); ls1+=(${ls1R[@]})
ls2L=(${ls1L[@]:2:4}); ls2R=(${ls1R[@]:2:4}) #Offset <<
ls2L+=(${ls1L[@]:0:2}); ls2R+=(${ls1R[@]:0:2})
ls2=(${ls2L[@]}); ls2+=(${ls2R[@]})
echo $(permutation "${p8[*]}" "${ls2[*]}") #p8
}
```
fK#(txtL,txtR)=(txtL+F(txtR,key#),txtR)
```bash
function round {
txtRoundInput=($1); shift
keyRound=($1)
txtL=(${txtRoundInput[@]:0:4}); txtR=(${txtRoundInput[@]:4:8}) #Division
txtE=($(permutation "${e[*]}" "${txtR[*]}")) #E/P
txtXor=($(xor "${txtE[*]}" "${keyRound[*]}")) #xor
txtXorL=(${txtXor[@]:0:4}); txtXorR=(${txtXor[@]:4:8}) #Division
txtSBox=($(sBox "${txtXorL[*]}" "sBoxS0")) #SBoxS0
txtSBox+=($(sBox "${txtXorR[*]}" "sBoxS1")) #SBoxS1
txtP4=($(permutation "${p4[*]}" "${txtSBox[*]}")) #P4
txtRoundL=($(xor "${txtP4[*]}" "${txtL[*]}")) #Xor
echo ${txtRoundL[@]} ${txtR[@]}
}
```
## Usage
```bash
Encryption: -e "txt[8 bits]" "key[8 bits]"
Decryption: -d "txt[8 bits]" "key[8 bits]"
Example: BASH sdes.sh -e "0 1 0 0 1 1 1 1" "0 0 1 0 0 1 0 1 1 1"
```
