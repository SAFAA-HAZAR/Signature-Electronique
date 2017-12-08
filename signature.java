 
package classicapplet2;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
/**
 *
 * @Author MLLE HAZAR Safaa  
 * @Filiére Génie informatique - sécurité informatique - S9
 */
public class signature extends Applet {
 
    
      //-@@--------------------------------------Déclaration des variables-------------------------------------@@--\\
   //--/\                                                                                                    /\---\\
  //---/\----------------------------------------------------------------------------------------------------/\----\\
    
       //-----------------Numero de classe de l'applet---------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
        private final static  byte CLA= (byte)0x80;
        
       //-----------------Variable_INS_APPEL_FONCTION----------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
 
        private final static  byte INS_SIGNER_FICHIER= (byte)0x03;
        private final static  byte INS_SHOW_PUB_Key_Exponent= (byte)0x00;
        private final static  byte INS_SHOW_PUB_Key_Modulus= (byte)0x05; 
        private final static  byte INS_VERIFIER_PIN= (byte)0x10;
        private final static  byte INS_CHANGE_PIN= (byte)0x11;
        private final static  byte INS_VERIFIER_PUK= (byte)0x12;
        private final static  byte INS_CHANGER_PIN_BLOCKE= (byte)0x13;
        private final static  byte INS_CHANGER_PUK= (byte)0x22;
        
       //------------------------Variable__PIN-----------------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
         
        private final static  byte Pin_taille= (byte)0x04;
        private final static  byte[] Initial_pin= {0x00,0x01,0x02,0x03};
        private final static  byte Nbre_essai_pin = 0x03;        
        OwnerPIN pin;
        
       //------------------------Variable__PUK-----------------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
        private final static  byte Puk_taille= (byte)0x08;
        private final static  byte[] Initial_puk= {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};       
        private final static  byte Nbre_essai_puk = 0x03;        
        OwnerPIN puk;
        
       //----------------------Declaration_des_cles------------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
 
        RSAPrivateKey m_privateKey;
        RSAPublicKey  m_publicKey;
        KeyPair m_keyPair;
        Signature signer;
    
   
       //------------------Declaration_des_tableaux------------------\\
      //                                                              \\
     //----------------------------------------------------------------\\
         short lenText;
         byte [] Text = new byte [255];
         byte [] MaSignature = new byte [255];
         short len;
     
    //-@@--------------------------------------Implementation de l'applet------------------------------------@@--\\
   //--/\                                                                                                    /\---\\
  //---/\----------------------------------------------------------------------------------------------------/\----\\
 
    
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new signature();
    }

     
    protected signature() {
        register();
           //--------- initiliser le Pin   --------------//
         pin =  new OwnerPIN(Nbre_essai_pin , Pin_taille);
         pin.update(Initial_pin,(short)0,(byte)Pin_taille);
        //--------- initiliser le Puk   --------------//
         puk = new OwnerPIN(Nbre_essai_puk , Puk_taille);
         puk.update(Initial_puk,(short)0,(byte)Puk_taille);
         Generer_key();

    }

     
    public void process(APDU apdu) {

      if(selectingApplet())
                return;
                byte [] buffer = apdu.getBuffer();
                if(buffer[ISO7816.OFFSET_CLA]!=CLA)
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                switch(buffer[ISO7816.OFFSET_INS]  ){
                
                case INS_VERIFIER_PIN: 
                    
                 Verifier_pin(apdu);
                break;
                 
                case INS_VERIFIER_PUK: 
                 Verifier_puk(apdu);
                break;
                        
                case INS_CHANGE_PIN: 
                    
                 Changer_pin_normal(apdu);
                break;
                
                case INS_CHANGER_PIN_BLOCKE: 
                 Changer_pin_blocke(apdu);
                break;
                case INS_CHANGER_PUK: 
                 Changer_puk(apdu);
                break;
                
                case INS_SIGNER_FICHIER: 
                    
                  if(!pin.isValidated())
                  ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 else
                 Recuperer_string_et_signer (apdu);
                break;
                   
                case INS_SHOW_PUB_Key_Exponent: 
                    
                   if(!pin.isValidated())
                  ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 else
                 afficher_cle_pub_Exponent(apdu);
                break;
                 
                case INS_SHOW_PUB_Key_Modulus: 
                    
                   if(!pin.isValidated())
                  ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 else
                 afficher_cle_pub_Modulus(apdu) ;           
                break;
                 
                 
                default:
                 ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

    }
    }
    
    
    
    
    
     
    //-@@-----------------------------------------Définitions des fonctions----------------------------------@@--\\
   //--/\                                                                                                    /\---\\
  //---/\----------------------------------------------------------------------------------------------------/\----\\
     
    
    //-----------------Génerer les clés : privée et publique + création de la signature   ---------------\\
   //                                                                                                     \\
  //-------------------------------------------------------------------------------------------------------\\
    private void Generer_key(){
                    m_privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,KeyBuilder.LENGTH_RSA_512,false);
                    m_publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_512,true);
                    m_keyPair = new KeyPair(KeyPair.ALG_RSA, (short) m_publicKey.getSize());
                    m_keyPair.genKeyPair();
                    m_publicKey = (RSAPublicKey) m_keyPair.getPublic();
                    m_privateKey = (RSAPrivateKey) m_keyPair.getPrivate();      
                    signer= Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false); 

    }
    
    
    //-----------------Récuperer String + signature---------------\\
   //                                                              \\
  //----------------------------------------------------------------\\
    
    private void Recuperer_string_et_signer(APDU   apdu){
                    byte buffer [] =    apdu.getBuffer();
                    short numBytesInput = apdu.setIncomingAndReceive();
                    lenText = 0;
        
                    while(numBytesInput>0)
                    {
                    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, Text, lenText, numBytesInput);
                    lenText+=numBytesInput;
                    numBytesInput = apdu.receiveBytes(ISO7816.OFFSET_CDATA);    
    }
        
                    try{
                    signer.init(m_privateKey, Signature.MODE_SIGN);
                    len = signer.sign(Text, (short)0, lenText, MaSignature, (short)0);
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short)len);
                    apdu.sendBytesLong(MaSignature, (short)0, len);
            
    }
                    catch(Exception e){
                      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

    }
    
    }
    
     
    
    //-------------------Affichage_des_cles-----------------------\\
   //                                                              \\
  //----------------------------------------------------------------\\
  
  //----------------afficher_l'exponent_de_la_le_publique------------\\
    
    
    private void afficher_cle_pub_Exponent(APDU   apdu){
                    byte buffer [] =apdu.getBuffer();
                    short length = m_publicKey.getExponent(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
    
    }
    
 //-------------------afficher_le_modulus_de_la_le_publique-------------\\
  
    private void afficher_cle_pub_Modulus(APDU   apdu){
                    byte buffer [] =apdu.getBuffer();
                    short length = m_publicKey.getModulus(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
    
    }
  
    //-------------------------Verifier_le_pin---------------------------\\
  
    private void Verifier_pin(APDU   apdu)
        { 
                    byte buffer [] =apdu.getBuffer();
                    if(buffer[ISO7816.OFFSET_P1]==0x01)
        {
                  //verifier_la_taille
                    if(buffer[ISO7816.OFFSET_LC] != 4)
                    ISOException.throwIt ( ISO7816.SW_WRONG_DATA );
                    else
                    if(!pin.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)4)){
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
        } 
        }
   //-------------------------Verifier_le_puk---------------------------\\
       
    private void Verifier_puk(APDU   apdu)
        { 
                    byte buffer [] =apdu.getBuffer();
                    if(buffer[ISO7816.OFFSET_P1]==0x02)
        {
                  //verifier_la_taille
                    if(buffer[ISO7816.OFFSET_LC] != 8)
                    ISOException.throwIt ( ISO7816.SW_WRONG_DATA );
                    else
                    if(!puk.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)8)){
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
        } 
        }
     //---------Changer_un_nouveau_pin_en_verifiant_l'ancien-pin--------\\
    
    private void Changer_pin_normal(APDU   apdu)
        { 
             
                   byte buffer [] =apdu.getBuffer();
                   if(!pin.isValidated()){
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
                   else{
                   if(buffer[ISO7816.OFFSET_LC] != 4)
                   ISOException.throwIt ( ISO7816.SW_WRONG_DATA );
                   pin.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)4);
                   
                   if(!pin.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)4)){
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
        }
        }
           
    //----------apres_blocage_du_pin_on_change_un_nouveau_pin_en_verifiant_le_puk--------\\   
    
    private void Changer_pin_blocke(APDU   apdu)
        { 
             
             
                   byte buffer [] =apdu.getBuffer();
                   if(!puk.isValidated())
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                   pin.resetAndUnblock();
                    if(buffer[ISO7816.OFFSET_LC] != 4)
                   ISOException.throwIt ( ISO7816.SW_WRONG_DATA );
                   
                   pin.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)4);
                   
                   if(!pin.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)4)){
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
        }
    
       private void Changer_puk(APDU   apdu)
        { 
             
             
                   byte buffer [] =apdu.getBuffer();
                   if(!puk.isValidated())
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                     if(buffer[ISO7816.OFFSET_LC] != 8)
                   ISOException.throwIt ( ISO7816.SW_WRONG_DATA );
                   
                   puk.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)8);
                   
                   if(!puk.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)8)){
                   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);}
        }
        }        
    
                  
         



//-----------------------------------------------FIN-------------------------------------------//
  




