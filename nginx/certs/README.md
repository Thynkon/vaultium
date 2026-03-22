paru -S liboqs

git clone https://github.com/open-quantum-safe/oqs-provider.git
./scripts/fullbuild.sh

openssl 3.5

openssl list -signature-algorithms -provider oqsprovider -provider-path ./oqs-provider/\_build/lib/oqsprovider.so
