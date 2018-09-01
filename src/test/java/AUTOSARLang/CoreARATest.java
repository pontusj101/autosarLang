package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreARATest {
        
    @Test
    public void testUserApplicationDoS(){
        ARA ara = new ARA("ARA");
        UserApplication userApplication = new UserApplication("UserApplication");
        ExecutionManagement em = new ExecutionManagement("ExecutionManagement");
        
        userApplication.addEm(em);
        ara.addUserApps(userApplication);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ARA.denialOfService,");
        userApplication.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testUserApplicationDoSViaOtherUserApp(){
        ARA ara = new ARA("ARA");
        UserApplication userApplication1 = new UserApplication("UserApplication1");
        UserApplication userApplication2 = new UserApplication("UserApplication2");
        ExecutionManagement em = new ExecutionManagement("ExecutionManagement");
        
        userApplication1.addEm(em);
        userApplication2.addEm(em);
        ara.addUserApps(userApplication1);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ARA.denialOfService,");
        userApplication1.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataDenyAccessViaUserApplication(){
        ARA ara = new ARA("ARA");
        UserApplication userApplication = new UserApplication("UserApplication");
        ExecutionManagement em = new ExecutionManagement("ExecutionManagement");
        Data data = new Data("Data");
        
        userApplication.addEm(em);
        userApplication.addData(data);
        ara.addUserApps(userApplication);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ARA.denialOfService,");
        userApplication.denialOfService.assertCompromisedInstantaneously();
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }  
    
    @Test
    public void testInforamtionRead(){
        ARA ara = new ARA("ARA");
        Information info = new Information("Information");
        
        ara.addInformation(info);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.compromise);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access -> ARA.informationLeak,");
        info.read.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testARAAttacks(){
        ARA ara = new ARA("ARA");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ara.access);
        attacker.attack();
        
        System.out.println("An attacker having ARA.access,");
        ara._adaptivePlatformAccess.assertCompromisedInstantaneously();
        ara.informationLeak.assertUncompromised();
        ara.messageInjection.assertUncompromised();
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
    public void testARAAccess(){
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