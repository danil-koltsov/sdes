#!/bin/sh
p10=(2 4 1 6 3 9 0 8 7 5)
p8=(5 2 6 3 7 4 9 8)
ip1=(3 0 2 4 6 1 7 5)
p4=(1 3 2 0)
ip=(1 5 2 0 3 7 4 6)
e=(3 0 1 2 1 2 3 0)
function permutation {
perm=($1); shift
bin=($1)
for j in ${perm[@]}; do
    echo ${bin[$j]}
done
}
function xor {
bin1=($1); shift
bin2=($1)
binLength=($((${#bin1[@]} - 1)))
for ((j=0; j<=$binLength; j++)); do
    echo $(( ${bin1[j]} ^ ${bin2[j]} ))
done
}
function sBox {
txtSBox=($1); shift
sBoxS=($1)
case "$sBoxS" in
    sBoxS0)
        declare -A sBoxSVersion=([0,0]=1 [0,1]=0 [0,2]=3 [0,3]=2
                                 [1,0]=3 [1,1]=2 [1,2]=1 [1,3]=0
                                 [2,0]=0 [2,1]=2 [2,2]=1 [2,3]=3
                                 [3,0]=3 [3,1]=1 [3,2]=3 [3,3]=1);;
    sBoxS1)
        declare -A sBoxSVersion=([0,0]=1 [0,1]=1 [0,2]=2 [0,3]=3
                                 [1,0]=2 [1,1]=0 [1,2]=1 [1,3]=3
                                 [2,0]=3 [2,1]=0 [2,2]=1 [2,3]=0
                                 [3,0]=2 [3,1]=1 [3,2]=0 [3,3]=3);;
esac
txtSBoxS01=($((${txtSBox[0]} * 2 ** 1 + ${txtSBox[3]} * 2 ** 0)))
txtSBoxS02=($((${txtSBox[1]} * 2 ** 1 + ${txtSBox[2]} * 2 ** 0)))
if [ ${sBoxSVersion[$txtSBoxS01,$txtSBoxS02]} = 0 ]; then
echo 0 0
fi
if [ ${sBoxSVersion[$txtSBoxS01,$txtSBoxS02]} = 1 ]; then
echo 0 1
fi
if [ ${sBoxSVersion[$txtSBoxS01,$txtSBoxS02]} = 2 ]; then
echo 1 0
fi
if [ ${sBoxSVersion[$txtSBoxS01,$txtSBoxS02]} = 3 ]; then
echo 1 1
fi
}
function keyGeneration1 {
keyIn=($1)
keyP10=($(permutation "${p10[*]}" "${keyIn[*]}")) #p10
keyL=(${keyP10[@]:0:5}); keyR=(${keyP10[@]:5:10}) #Division
ls1L=(${keyL[@]:1:4}); ls1R+=(${keyR[@]:1:4}) #Offset <
ls1L[5]=${keyL[0]}; ls1R[5]=${keyR[0]}
ls1=(${ls1L[@]}); ls1+=(${ls1R[@]})
echo $(permutation "${p8[*]}" "${ls1[*]}") #p8
}
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
if [[ $# < 3 ]] || [[ "$1" != "-e" && "$1" != "-d" ]]; then
    echo "Usage: -e|-d \"txt[8 bits]\" \"key[10 bits]\""
    exit 0
fi
func=("$1"); shift
txt=("$1"); shift
key=("$1")
case "${func}" in
    "-e")
        txtCipher=$(encryption "${txt[*]}" "${key[*]}")
        echo Cipher txt: ${txtCipher[@]};;
    "-d")
        txtDecrypted=$(decryption "${txt[*]}" "${key[*]}")
        echo Decrypted txt: ${txtDecrypted[@]};;
esac
#  sdes.sh
#
#
#  Created by danil-koltsov
#
