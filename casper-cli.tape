Output casper-cli.gif

Set FontSize 15
Set Width 1600
Set Height 650
Set Shell zsh

Type "casper-cli wallet create devnet --seed default --domain casper-unsafe-devnet-v1 --unencrypted"

# File based storage
Sleep 1s
Enter

# File based storage
Sleep 1s
Down

Sleep 2s
Enter

# Confirm default location
Sleep 1s
Enter

Sleep 1s
Type "casper-cli wallet list"
Sleep 1s
Enter

Sleep 1s
Type "casper-cli wallet derive devnet --start 0 --count 4 --name 'validator-{index1}'"
Sleep 1s
Enter

Sleep 1s
Type "casper-cli wallet derive devnet --start 100 --count 4 --name 'user-{counter1}'"
Sleep 1s
Enter

Sleep 1s
Type "casper-cli wallet info devnet"
Sleep 1s
Enter

Sleep 1
Type "casper-cli tx transfer --from devnet:user-1 --to devnet:user-2 --amount 5 --raw | tee txn.txt
Sleep 1s
Enter

Sleep 5s
Type "casper-cli tx get $(<txn.txt)
Sleep 1s
Enter

Type "casper-cli balance devnet:user-2
Sleep 5s
Enter

Type "casper-cli tx put --from devnet:user-1 /tmp/do_nothing_stored.wasm --install-upgrade --payment-amount 500 --raw  | tee txn.txt
Sleep 1s
Enter

Sleep 5s
Type "casper-cli tx call --from devnet:user-1 do_nothing_hash delegate --arg 'amount:u512=100' --simulate
Sleep 1s
Enter

Type "casper-cli tx call --from devnet:user-1 do_nothing_hash delegate --arg 'amount:u512=100' --raw | tee txn.txt
Sleep 1s
Enter

Sleep 5s

Type "casper-cli tx get $(<txn.txt)
Sleep 1s
Enter
Sleep 5s
