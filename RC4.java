//RC4 class - Please include in both transmitter and receiver packages

package transmitter;
public class RC4 
{	
	//Declare S array, T array and keylen fields
	
	private final byte[] S = new byte[256];
    private final byte[] T = new byte[256];
    private final int KEYLEN;

    public RC4(final byte[] KEY) 
    {
        if (KEY.length < 1 || KEY.length > 256) //Checking if key length is valid or not
        {
            throw new IllegalArgumentException("Error! Key length must range between 1 and 256 bytes");
        } 
        
        else 
        {
        	KEYLEN = KEY.length;
            
            for (int i = 0; i < 256; i++) //Initializing S and T arrays
            {
                S[i] = (byte) i;
                T[i] = KEY[i % KEYLEN]; //The first keylen elements of T are copied from key and this is repeated as many times as necessary to fill out T.
            }
            
            int j = 0;
            
            for (int i = 0; i < 256; i++) //Using T to produce an initial permutation of S
            {
                j = (j + S[i] + T[i]) & 0xFF;
                S[i] ^= S[j]; //XORing and Swapping S[i] and S[j]
                S[j] ^= S[i];
                S[i] ^= S[j];
            }
        }
    }

    public byte[] encrypt(final byte[] PLAINTEXT) //encrypt method generates stream and encrypts plaintext bytes
    {
        final byte[] CIPHERTEXT = new byte[PLAINTEXT.length]; //Declaring a ciphertext array and initializing it with the same length as plaintext array
        int i = 0, j = 0, k, t; //Declare fields necessary for encryption
        
        //Stream generation involves starting with S[0] and going through to S[255], and, for each S[i], swapping S[i] with another byte in S
        
        for (int counter = 0; counter < PLAINTEXT.length; counter++) 
        {
            i = (i + 1) & 0xFF; 
            j = (j + S[i]) & 0xFF;
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];
            t = (S[i] + S[j]) & 0xFF;
            k = S[t];
            CIPHERTEXT[counter] = (byte) (PLAINTEXT[counter] ^ k); //To encrypt, XOR the value of k with the next byte of plaintext
        }
        
        return CIPHERTEXT;
    }

    public byte[] decrypt(final byte[] CIPHERTEXT)
    {
        return encrypt(CIPHERTEXT); //To decrypt, XOR the value k with the next byte of ciphertext.
    }
}
