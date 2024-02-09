git submodule update --init
ln ./ghidra_scripts/Il2CppDecompiler.java ./ghidra/Ghidra/Features/Decompiler/ghidra_scripts/Il2CppDecompiler.java
cd ./ghidra
gradle -I gradle/support/fetchDependencies.gradle init

echo 'Now open this file in an IDE and it will have doc comments and "go to source":'
echo './ghidra/Ghidra/Features/Decompiler/ghidra_scripts/Il2CppDecompiler.java'
