import socket
import ssl
import OpenSSL
import certifi 

def get_certificates( hostname):
    """Retrieves all SSL certificates in the chain for a given hostname."""
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_fieldname= hostname) as s:
        s.connect(( hostname, 443))
        cert_chain = s.getpeercert(True)  # Get certificates in binary format
        x509_chain = []
        for cert in cert_chain:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            x509_chain.append(x509)
        return x509_chain

def analyze_certificate_chain(cert_chain):
    """Analyzes the chain, checking issuer against trusted root authorities."""
    trusted_root_store = OpenSSL.crypto.X509Store()
    trusted_root_store.add_cert(certifi.where())  # Load CAs from 'certifi'

    for i in range(len(cert_chain)):
        cert = cert_chain[i]
        issuer = cert.get_issuer()

        # Check against trusted roots
        issuer_context = OpenSSL.crypto.X509StoreContext(trusted_root_store, cert)
        try:
            issuer_context.verify_certificate()  
            print(f"-> Certificate #{i} is trusted.")
        except OpenSSL.crypto.X509StoreContextError:
            print(f"-> Potential issue with certificate #{i} (untrusted)")
            print("   Issuer:", issuer.get_components())

if __name__ == "__main__":
    user_input = input("Enter the website URL: ")

    try:
        cert_chain = get_certificates(user_input)
        analyze_certificate_chain(cert_chain)
    except Exception as e:
        print(f"An error occurred: {e}") 
