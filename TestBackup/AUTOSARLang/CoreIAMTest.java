package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreIAMTest {
    
    @Test
    public void testServiceAccessViaIAM(){
        IAM iam = new IAM("IAM");
        Service service = new Service("Service");

        iam.addApServices(service);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        service.access.assertCompromisedInstantaneously();
        
        //Further attacks
        service._softwareAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testCryptoStackAccessViaIAM(){
        IAM iam = new IAM("IAM");
        CryptoStack cryptoStack = new CryptoStack("CryptoStack");

        iam.addCryptoStack(cryptoStack);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        cryptoStack.access.assertCompromisedInstantaneously();
        
        //Further attacks
        cryptoStack._softwareAccess.assertCompromisedInstantaneously();
        cryptoStack.denialOfService.assertCompromisedInstantaneously();
        cryptoStack.circumventCryptoService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOSAccessAndAttacksViaIAM(){
        IAM iam = new IAM("IAM");
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");

        iam.addOs(operatingSystem);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        operatingSystem.access.assertCompromisedInstantaneously();
        
        //Further attacks
        operatingSystem._softwareAccess.assertCompromisedInstantaneously();
        operatingSystem.denialOfService.assertCompromisedInstantaneously();
        operatingSystem.dataInjection.assertCompromisedInstantaneously();
        operatingSystem.memoryCorruption.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDatadDenyAccessViaIAM(){
        IAM iam = new IAM("IAM");
        Data data = new Data("Data");

        iam.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAttacksViaIAMThenManifest(){
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        AdaptiveApplication adaptiveApplication = new AdaptiveApplication("AdaptiveApplication");
        
        Manifest manifest1 = new Manifest("Manifest1");
        AdaptiveApplication adaptiveApplication1 = new AdaptiveApplication("AdaptiveApplication1");
        adaptiveApplication1.addConfigurationFile(manifest1);
        
        manifest.addOwnerApp(adaptiveApplication);
        manifest.addOtherApps(adaptiveApplication1);
        iam.addPolicies(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        adaptiveApplication1.access.assertCompromisedInstantaneously();
        adaptiveApplication1.denialOfService.assertCompromisedInstantaneously();
        
        //From Access
        adaptiveApplication1.provideFakeService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationDoSViaIAMThenManifest(){
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        AdaptiveApplication adaptiveApplication = new AdaptiveApplication("AdaptiveApplication");
        
        manifest.addOwnerApp(adaptiveApplication);
        iam.addPolicies(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testManifestRWDViaIAM(){
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        
        iam.addPolicies(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        manifest.read.assertCompromisedInstantaneously();
        manifest.write.assertCompromisedInstantaneously();
        manifest.delete.assertCompromisedInstantaneously();
        manifest.readCapability.assertCompromisedInstantaneously();
        manifest.modifyCapabily.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMAttacks(){
        IAM iam = new IAM("IAM");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        iam._softwareAccess.assertCompromisedInstantaneously();
        iam.denialOfService.assertCompromisedInstantaneously();
        iam.circumventPEP.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMAccess2(){
        IAM iam = new IAM("IAM");        
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having IAM.bypassAccessControl,");
        iam.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMAccess(){
        IAM iam = new IAM("IAM");        
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.connect);
        attacker.addAttackPoint(iam.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having IAM.connect and IAM.authenticate,");
        iam.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
