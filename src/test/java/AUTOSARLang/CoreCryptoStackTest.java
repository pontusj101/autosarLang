/*package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreCryptoStackTest {
    
    @Test
    public void testEncDataRWViaCryptoStack(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");
        //CryptographicKey cryptographicKey = new CryptographicKey("CryptographicKey");
        EncryptedData encryptedData = new EncryptedData("EncryptedData");
        
        cryptoStack.addEncryptedData(encryptedData);
        cryptoStack.addDecryptedData(encryptedData);
        //cryptoStack.addKeys(cryptographicKey);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having CryptoStack.access,");
        encryptedData.readEncrypted.assertUncompromised(); //??
        encryptedData.writeEncrypted.assertUncompromised(); //??
        System.out.println();
    }
    
    @Test
    public void testKeysReadViaCryptoStack(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");
        CryptographicKey cryptographicKey = new CryptographicKey("CryptographicKey");

        cryptoStack.addKeys(cryptographicKey);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        cryptographicKey.read.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testManifestRWDViaCryptoStackThenIAM(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        
        iam.addPolicies(manifest);
        cryptoStack.addIam(iam);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having CryptoStack.access,");
        manifest.read.assertCompromisedInstantaneously();
        manifest.write.assertCompromisedInstantaneously();
        manifest.delete.assertCompromisedInstantaneously();
        manifest.readCapability.assertCompromisedInstantaneously();
        manifest.modifyCapabily.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMAccessViaCryptoStack(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");
        IAM iam = new IAM("IAM");
        
        cryptoStack.addIam(iam);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having CryptoStack.access,");
        iam.access.assertCompromisedInstantaneously();
        
        //Further attacks
        iam._softwareAccess.assertCompromisedInstantaneously();
        iam.denialOfService.assertCompromisedInstantaneously();
        iam.circumventPEP.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDatadDenyAccessViaCryptoStack(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");        
        Data data = new Data("Data");

        cryptoStack.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having CryptoStack.access,");
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testCryptoStackttacks(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");        
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        cryptoStack._softwareAccess.assertCompromisedInstantaneously();
        cryptoStack.denialOfService.assertCompromisedInstantaneously();
        cryptoStack.circumventCryptoService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testCryptoStackAccess2(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");        
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having ICryptoStackAM.bypassAccessControl,");
        cryptoStack.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testCryptoStackAccess(){
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");        
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(cryptoStack.connect);
        attacker.addAttackPoint(cryptoStack.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having CryptoStack.connect and CryptoStack.authenticate,");
        cryptoStack.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}

*/