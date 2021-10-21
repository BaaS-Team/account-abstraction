//run a single op
// "yarn run runop [--network ...]"
import hre, {ethers} from 'hardhat'
import {objdump} from "../test/testutils";
import {AASigner} from "./ethers/AASigner";
import {TestCounter__factory, EntryPoint__factory} from '../typechain'
import '../test/aa.init'
import {parseEther} from "ethers/lib/utils";
import {debugRpcUrl} from "./ethers/debugRpcServer";

(async () => {
  await hre.run('deploy')
  console.log('net=', hre.network.name)
  if (hre.network.name != 'hardhat')
    await hre.run('etherscan-verify')
  const [entryPointAddress, walletAddress, testCounterAddress] = await Promise.all([
    hre.deployments.get('EntryPoint').then(d => d.address),
    hre.deployments.get('SimpleWallet').then(d => d.address),
    hre.deployments.get('TestCounter').then(d => d.address),
  ])

  let provider = ethers.provider;
  const ethersSigner = provider.getSigner()

  const url = process.env.AA_URL

  const aasigner = new AASigner(ethersSigner, {
    entryPointAddress,
    sendUserOpRpc: url, // O?? debugRpcUrl(entryPointAddress, ethersSigner)
    debug_handleOpSigner: url == null ? ethersSigner : undefined  //use debug signer only if no URL
  })
  await aasigner.connectWalletAddress(walletAddress)
  const myAddress = await aasigner.getAddress()
  if (await provider.getBalance(myAddress) < parseEther('0.01')) {
    console.log('prefund wallet')
    await ethersSigner.sendTransaction({to: myAddress, value: parseEther('0.01')})
  }

  //usually, a wallet will deposit for itself (that is, get created using eth, run "addDeposit" for itself
  // and from there on will use deposit
  // for testing,
  const entryPoint = EntryPoint__factory.connect(entryPointAddress, ethersSigner)
  const info = await entryPoint.getStakeInfo(myAddress)
  const currentStake = info.stake.toString()
  console.log('current stake=', currentStake)

  if (info.stake.lte(parseEther('0.01'))) {
    console.log('depositing for wallet')
    entryPoint.addDepositTo(myAddress, {value: parseEther('0.01')})
  }

  const testCounter = TestCounter__factory.connect(testCounterAddress, aasigner)

  const prebalance = await provider.getBalance(myAddress)
  console.log('current counter=', await testCounter.counters(myAddress), 'balance=', prebalance, 'stake=', currentStake)
  const ret = await testCounter.count()
  console.log('waiting for mine, tmp.hash=', ret.hash)
  const rcpt = await ret.wait()
  console.log('rcpt', rcpt.transactionHash, `https://dashboard.tenderly.co/tx/kovan/${rcpt.transactionHash}/gas-usage`)
  let gasPaid = prebalance.sub(await provider.getBalance(myAddress))
  console.log('counter after=', await testCounter.counters(myAddress), 'paid=', gasPaid.toNumber() / 1e9, 'gasUsed=', rcpt.gasUsed)
  const logs = await entryPoint.queryFilter('*' as any, rcpt.blockNumber)
  console.log(logs.map((e: any) => ({ev: e.event, ...objdump(e.args!)})))


})().then(()=>process.exit())
