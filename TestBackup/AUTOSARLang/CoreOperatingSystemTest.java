package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreOperatingSystemTest {
    
    OperatingSystem operatingSystem;
    IAM iam;
    
    private void initializeObjects(){
        operatingSystem = new OperatingSystem("OperatingSystem");
        iam = new IAM("IAM");
        operatingSystem.addIamProgram(iam);
    }
    
    @Test
    public void testOSConditionally(){
        operatingSystem = new OperatingSystem("OperatingSystem", true);
        iam = new IAM("IAM");
        operatingSystem.addIamProgram(iam);        

        Account account = new Account("Account");
        operatingSystem.addAssignedAccounts(account);
        
        Data data = new Data("Data");
        operatingSystem.addPrccessingData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        data.read.assertUncompromised();
        account.compromise.assertUncompromised();
        System.out.println();
    }
    
    
    @Test
    public void testECUDoS(){
        initializeObjects();
        ECU ecu = new ECU("ECU");
        operatingSystem.addEcuMachine(ecu);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        ecu.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAccountCompromise(){
        initializeObjects();
        Account account = new Account("Account");
        operatingSystem.addAssignedAccounts(account);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        account.compromise.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataRWD(){
        initializeObjects();
        Data data = new Data("Data");
        operatingSystem.addPrccessingData(data);
        operatingSystem.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        data.read.assertCompromisedInstantaneously();
        data.write.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAttacks(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        operatingSystem._softwareAccess.assertCompromisedInstantaneously();
        operatingSystem.dataInjection.assertCompromisedInstantaneously();
        operatingSystem.memoryCorruption.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAccess2(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having OS.bypassAccessControl,");
        operatingSystem.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAccess(){
        initializeObjects();
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.connect);
        attacker.addAttackPoint(operatingSystem.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having OS.connect and OS.authenticate,");
        operatingSystem.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
