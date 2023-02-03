from .exec import  exec_subprocess_with_live_output, exec_subprocess_in_background
from nest.topology.address import Address
from nest.engine import util
import logging
logger = logging.getLogger(__name__)


def create_tls_client(ns_name: str, dest_address: str):
    """
    When your browser makes an HTTPS connection, a TCP request is sent via port 443. The TLS/SSL 
    port is 443, HTTPS uses the TLS/SSL certificates to keep the port connections secure that’s 
    why we are using port 443 for securing the connection.

    Parameters
    ----------
    ns_name : str
        Network namespace to run TLS from.

    dest_address : str
        Destination address which we want to establish TLS connection.
    
    """
    dest_addr = Address.get_addr(dest_address, False)
    exec_subprocess_in_background(
                                f'''ip netns exec {ns_name} 
                                openssl s_client 
                                -connect {dest_addr}:443'''
    )
    logger.info("TLS client is created.")

def create_tls_server(ns_name:str):
    """
    Here we will make secure connection between client and server using OpenSSL.

    OpenSSL is an all-around cryptography library that offers an open-source application 
    of the TLS protocol.OpenSSL contains an open-source implementation of the SSL and 
    TLS protocols.

    Parameters
    ----------
    ns_name : str
        Network namespace which we are going to make TLS server.

    """

    exec_subprocess_in_background(
                                f'''ip netns exec {ns_name} 
                                openssl s_server 
                                -key key.pem 
                                -cert cert.pem 
                                -accept 443 
                                -www'''
    )
    logger.info("TLS server is created.")
    logger.info("TLS server is running...")

def certificate(country_Name:str='.', state_Name:str='.', locality_Name:str='.', organization_Name:str='.',
                organizational_Unit_Name:str='.', common_Name:str='.', email_Address:str='.'):

                """
                It generates a new private key (-newkey) using the RSA algorithm with a 2048-bit key 
                length (rsa:2048) without using a passphrase (-nodes) and then creates the key 
                file with a name of key.pem (-keyout key.pem).
                """
                    
                if len(country_Name)==2:
                    exec_subprocess_with_live_output(
                                        f'''openssl 
                                        req -new 
                                        -newkey rsa:2048
                                        -nodes 
                                        -keyout key.pem
                                        -x509
                                        -days 365
                                        -out cert.pem
                                        -subj /C={country_Name}/ST={state_Name}/L={locality_Name}/O={organization_Name}/OU={organizational_Unit_Name}/CN={common_Name}/emailAddress={email_Address}
                                        '''
                    )
                    
                    logger.info("Certificate is created.")
                    
                else:
                    
                    logger.error("Country name length should be exactly two.")
