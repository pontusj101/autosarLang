package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreIAMTest {

    @Test
    public void testDataAttack(){
        IAM iam = new IAM("IAM");
        Data data = new Data("Data");
        iam.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        data.denyAccess.assertCompromisedInstantaneously();
        data.requestAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testInformationReadViaManifest(){
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        Information info = new Information("Information");
                
        manifest.addInformation(info);
        iam.addProcessedCapabilities(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        info.read.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testFCBypassAccessControl(){
        IAM iam = new IAM("IAM");
        FunctionalCluster fc = new FunctionalCluster("FunctionalCluster");
        
        iam.addPlatformApps(fc);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access -> IAM.circumventPDP,");
        fc.bypassAccessControl.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testFCAuthenticateViaManifestRead(){
        IAM iam = new IAM("IAM");
        Manifest manifest = new Manifest("Manifest");
        FunctionalCluster fc = new FunctionalCluster("FunctionalCluster");
        
        manifest.addPlatformApps(fc);
        iam.addProcessedPolicies(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        fc.authenticate.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testManifestRead(){
        IAM iam = new IAM("IAM");
        Manifest appManifest = new Manifest("ApplicationManifest");
        Manifest serManifest = new Manifest("ServiceInstanceManifest");
        
        iam.addProcessedPolicies(serManifest);
        iam.addProcessedCapabilities(appManifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        appManifest.read.assertCompromisedInstantaneously();
        serManifest.read.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testIAMAttacks(){
        IAM iam = new IAM("IAM");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(iam.access);
        attacker.attack();
        
        System.out.println("An attacker having IAM.access,");
        iam._adaptivePlatformAccess.assertCompromisedInstantaneously();
        iam.denialOfService.assertCompromisedInstantaneously();
        iam.circumventPDP.assertCompromisedInstantaneously();
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
