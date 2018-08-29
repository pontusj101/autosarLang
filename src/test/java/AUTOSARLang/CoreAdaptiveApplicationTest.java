package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreAdaptiveApplicationTest {
    
    AdaptiveApplication adaptiveApplication;
    ExecutionManagement em;
    
    private void initializeObjects(){
        adaptiveApplication = new AdaptiveApplication("AdaptiveApplication");
        em = new ExecutionManagement("ExecutionManagement");
        adaptiveApplication.addEm(em);
    }
    
    @Test
    public void testDoSFromAccess(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDoSFromShutdown(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.shutdown);
        attacker.attack();
        
        System.out.println("An attacker having AA.shutdown,");
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataAccess(){
        initializeObjects();
        Data data = new Data("Data");
        adaptiveApplication.addData(data);
        
        PersistentData perData = new PersistentData("PersistentData");
        adaptiveApplication.addPersistentData(perData);
        
        Manifest manifest = new Manifest("Manifest");
        adaptiveApplication.addApplicationManifests(manifest);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        data.requestAccess.assertCompromisedInstantaneously();
        perData.requestAccess.assertCompromisedInstantaneously();
        manifest.requestAccess.assertCompromisedInstantaneously();

        data.read.assertUncompromised();
        perData.read.assertUncompromised();
        manifest.read.assertUncompromised(); 
        System.out.println();
    }
    
    @Test
    public void testFCAccess(){
        initializeObjects();
        FunctionalCluster fc = new FunctionalCluster("FunctionalCluster");
        adaptiveApplication.addFunctionalCluster(fc);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        fc.requestAccess.assertCompromisedInstantaneously();
        fc.access.assertUncompromised();
        fc.launch.assertUncompromised();
        fc.shutdown.assertUncompromised();
        fc.circumventPEP.assertUncompromised();
        System.out.println();
    }
    
    @Test
    public void testFCAccessIAMAuth(){
        initializeObjects();
        FunctionalCluster fc = new FunctionalCluster("FunctionalCluster");
        IAM iam = new IAM("IAM");
        fc.addIam(iam);
        iam.addPlatformApps(fc);
        adaptiveApplication.addFunctionalCluster(fc);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        fc.requestAccess.assertCompromisedInstantaneously();
        iam.requestAuthentication.assertCompromisedInstantaneously();
        fc.authenticate.assertCompromisedInstantaneously();
        //fc.access.assertCompromisedInstantaneously();???
        System.out.println();
    }
    
    @Test
    public void testARAAccess(){
        initializeObjects();
        ARA ara = new ARA("ARA");
        adaptiveApplication.addFcInterfaces(ara);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        ara.access.assertCompromisedInstantaneously();
        ara.denialOfService.assertCompromisedInstantaneously();
        ara.informationLeak.assertUncompromised();
        ara.messageInjection.assertUncompromised();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAttacks(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.access);
        attacker.attack();
        
        System.out.println("An attacker having AA.access,");
        adaptiveApplication._adaptivePlatformAccess.assertCompromisedInstantaneously();
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        adaptiveApplication.provideIllegitimateService.assertCompromisedInstantaneously();
        adaptiveApplication.requestService.assertCompromisedInstantaneously();
        System.out.println();
    }
  
    @Test
    public void testDataDenyAccess(){
        initializeObjects();
        Data data = new Data("Data");
        adaptiveApplication.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having AA.denialOfService,");
        data.denyAccess.assertUncompromised();//???
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAccess4(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.compromise);
        attacker.attack();
        
        System.out.println("An attacker having AA.compromise,");
        adaptiveApplication.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAdaptiveApplicationAccess3(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(adaptiveApplication.launch);
        attacker.attack();
        
        System.out.println("An attacker having AA.launch,");
        adaptiveApplication.access.assertCompromisedInstantaneously();
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
