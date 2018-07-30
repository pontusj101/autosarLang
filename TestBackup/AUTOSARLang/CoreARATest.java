package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreARATest {
    
    //Others related with Machine can be added here
    
    @Test
    public void testAdaptiveApplicationDoS(){
        ARA ara = new ARA("ARA");
        AdaptiveApplication adaptiveApplication = new AdaptiveApplication("AdaptiveApplication");
        Manifest manifest = new Manifest("Manifest");
        
        adaptiveApplication.addConfigurationFile(manifest);
        ara.addRequestingApps(adaptiveApplication);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ARA.denialOfService,");
        adaptiveApplication.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testInformationViaDataflowViaData(){
        ARA ara = new ARA("ARA");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        Information info = new Information("Information");
        
        data.addInformation(info);
        dataflow.addData(data);
        ara.addRuntimeDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        info.read.assertCompromisedInstantaneously();
        info.write.assertCompromisedInstantaneously();
        info.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataViaDataflow(){
        ARA ara = new ARA("ARA");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        
        data.addDataflow(dataflow);
        ara.addRuntimeDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        data.read.assertCompromisedInstantaneously();
        data.write.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataDenyAccess(){
        ARA ara = new ARA("ARA");
        Data data = new Data("Data");
        
        ara.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataflow(){
        ARA ara = new ARA("ARA");
        Dataflow dataflow = new Dataflow("Dataflow");
        ara.addRuntimeDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        dataflow.eavesdrop.assertCompromisedInstantaneously();
        dataflow.manInTheMiddle.assertCompromisedInstantaneously();
        dataflow.denialOfService.assertCompromisedInstantaneously();
        dataflow.request.assertCompromisedInstantaneously();
        dataflow.respond.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testARAAttacks(){
        ARA ara = new ARA("ARA");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        ara._softwareAccess.assertCompromisedInstantaneously();
        ara.informationLeak.assertCompromisedInstantaneously();
        ara.messageInjection.assertCompromisedInstantaneously();
        ara.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testARAAccess2(){
        ARA ara = new ARA("ARA");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having ARA.bypassAccessControl,");
        ara.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testARAccess(){
        ARA ara = new ARA("ARA");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.connect);
        attacker.addAttackPoint(ara.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having ARA.connect and ARA.authenticate,");
        ara.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
