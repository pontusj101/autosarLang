package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreAdaptiveApplicationTest {
    
    AdaptiveApplication adaptiveApplication;
    Manifest manifest;
    
    private void initializeObjects(){
        adaptiveApplication = new AdaptiveApplication("AdaptiveApplication");
        manifest = new Manifest("Manifest");
        adaptiveApplication.addConfigurationFile(manifest);
    }
    
    @Test
    public void testOtherAAsAccess(){
        initializeObjects();
        AdaptiveApplication aa1 = new AdaptiveApplication("AA1");
        Manifest manifest1 = new Manifest("AA1Manifest");
        manifest1.addOtherApps(aa1);
        
        adaptiveApplication.addManifestFiles(manifest1);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        aa1.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOthersManifestAttacks(){
        initializeObjects();
        AdaptiveApplication aa1 = new AdaptiveApplication("AA1");
        Manifest manifest1 = new Manifest("AA1Manifest");

        aa1.addConfigurationFile(manifest1);
        adaptiveApplication.addManifestFiles(manifest1);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        manifest1.readCapability.assertCompromisedInstantaneously();
        manifest1.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOwnManifestAttacks(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.authenticate);
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access AND/OR AA.authenticate,");
        manifest.modifyCapabily.assertCompromisedInstantaneously();
        manifest.read.assertCompromisedInstantaneously();
        manifest.readCapability.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testS2SMappingAttacks(){
        initializeObjects();
        SignalToServiceMappingService s2s = new SignalToServiceMappingService("S2SMapping");
        adaptiveApplication.addServiceConverter(s2s);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.authenticate);
        attacker.attack();
        
        System.out.println("An attacker having AA.authenticate,");
        s2s.access.assertCompromisedInstantaneously();
        s2s.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMCircumventPEP(){
        initializeObjects();
        IAM iam = new IAM("IAM");
        adaptiveApplication.addImaAPI(iam);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        iam.circumventPEP.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataRqstDenyAccess(){
        initializeObjects();
        Data data = new Data("Data");
        adaptiveApplication.addPersistentData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        data.requestAccess.assertCompromisedInstantaneously();
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAttacks(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        adaptiveApplication._softwareAccess.assertCompromisedInstantaneously();
        adaptiveApplication.provideFakeService.assertCompromisedInstantaneously();
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        adaptiveApplication.provideFakeService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAccess2(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having AA.bypassAccessControl,");
        adaptiveApplication.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAccess(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.connect);
        attacker.addAttackPoint(adaptiveApplication.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having AA.connect and AA.authenticate,");
        adaptiveApplication.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
