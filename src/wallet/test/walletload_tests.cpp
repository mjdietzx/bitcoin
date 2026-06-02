// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <script/descriptor.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool HavePrivateKeys(const SigningProvider&) const override { return false; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
    bool HasScripts() const override { return true; }
    std::vector<std::string> Warnings() const override { return {}; }
    uint32_t GetMaxKeyExpr() const override { return 0; }
    size_t GetKeyCount() const override { return 0; }
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tpubD6NzVbkrYhZ4Y4S7m6Y5s9GD8FqEMBy56AGphZXuagajudVZEnYyBahZMgHNCTJc2at82YX6s8JiL1Lohu5A3v1Ur76qguNH4QVQ7qYrBQx/86'/1'/0'/0/*)#8pn8tzdt";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::UNKNOWN_DESCRIPTOR);
    }

}

//! The id an older software version would have stored for this descriptor: the hash of its
//! non-compat string form (DescriptorID() uses the compat form). These differ whenever the
//! descriptor's canonicalization has since changed, e.g. for Miniscript.
static uint256 LegacyDescriptorID(const Descriptor& desc)
{
    const std::string desc_str{desc.ToString(/*compat_format=*/false)};
    uint256 id;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(desc_str.data()), desc_str.size()).Finalize(id.begin());
    return id;
}

//! The example descriptors below use testnet (tpub) keys, so run on regtest where they are valid.
struct RegtestingSetup : public TestingSetup {
    RegtestingSetup() : TestingSetup(ChainType::REGTEST) {}
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptor_id_mismatch, RegtestingSetup)
{
    // A wallet whose descriptor-record key (its DescriptorID) was computed by an older software
    // version can differ from the id the current code derives from the same descriptor, because the
    // descriptor's canonical string form changed. Such a wallet must still load, stay usable, and
    // re-importing the descriptor must not create a duplicate ScriptPubKeyMan.
    for (const std::string& desc_str : {
        // "Decaying" multisig examples from doc/descriptors.md (wsh and tr variants).
        std::string{R"(wsh(thresh(4,pk([7258e4f9/44h/1h/0h]tpubDCZrkQoEU3845aFKUu9VQBYWZtrTwxMzcxnBwKFCYXHD6gEXvtFcxddCCLFsEwmxQaG15izcHxj48SXg1QS5FQGMBx5Ak6deXKPAL7wauBU/<0;1>/*),s:pk([c80b1469/44h/1h/0h]tpubDD3UwwHoNUF4F3Vi5PiUVTc3ji1uThuRfFyBexTSHoAcHuWW2z8qEE2YujegcLtgthr3wMp3ZauvNG9eT9xfJyxXCfNty8h6rDBYU8UU1qq/<0;1>/*),s:pk([4e5024fe/44h/1h/0h]tpubDDLrpPymPLSCJyCMLQdmcWxrAWwsqqssm5NdxT2WSdEBPSXNXxwbeKtsHAyXPpLkhUyKovtZgCi47QxVpw9iVkg95UUgeevyAqtJ9dqBqa1/<0;1>/*),s:pk([3b1d1ee9/44h/1h/0h]tpubDCmDTANBWPzf6d8Ap1J5Ku7J1Ay92MpHMrEV7M5muWxCrTBN1g5f1NPcjMEL6dJHxbvEKNZtYCdowaSTN81DAyLsmv6w6xjJHCQNkxrsrfu/<0;1>/*),sln:after(840000),sln:after(1050000),sln:after(1260000))))"},
        std::string{R"(tr(musig([93c34b55/44h/1h/0h]tpubDD637qigtWM7nJWDpG2bSNKtRwbwhsBhUSPBn2x7kwa4HQci697BpccQBy4aamu7vUuEgmHe9w9JTHjVnnj3ENdFC57xUaAHDipWqYRFf4M/<0;1>/*,[c9c90f7a/44h/1h/0h]tpubDCrZoKT5TeXQK66t9pXgZ4WZaLT1yy5rqY9Nev4oahSLY1x8GzqDqY1bs4MwVRCjJQEjKmw35saW24iyio7t2mfuy5dbffbe4cUTH5nuLfS/<0;1>/*,[ca5af974/44h/1h/0h]tpubDCszKRG2jLDx9pEePF6mnmxPwkNASFiJ5C65Gzw516bSvtvF1EbmKiT4XuxnvRdQ449YyKXYgoEuUjtod7467zrVtmCFrTgsXWzPNZ6SuX3/<0;1>/*,[e3132379/44h/1h/0h]tpubDDkB59UH9e2jRnxNvUhm7yGqq3csxMHH4YFiHN4EyhwYsE4styvXFy3GvaYUG3JHHGkKbbyuR29hDcCxDEZ2m5sg77ov5HMt7VMHn27Dnav/<0;1>/*),{and_v(v:after(840000),multi_a(3,[93c34b55/44h/1h/0h]tpubDD637qigtWM7nJWDpG2bSNKtRwbwhsBhUSPBn2x7kwa4HQci697BpccQBy4aamu7vUuEgmHe9w9JTHjVnnj3ENdFC57xUaAHDipWqYRFf4M/<0;1>/*,[c9c90f7a/44h/1h/0h]tpubDCrZoKT5TeXQK66t9pXgZ4WZaLT1yy5rqY9Nev4oahSLY1x8GzqDqY1bs4MwVRCjJQEjKmw35saW24iyio7t2mfuy5dbffbe4cUTH5nuLfS/<0;1>/*,[ca5af974/44h/1h/0h]tpubDCszKRG2jLDx9pEePF6mnmxPwkNASFiJ5C65Gzw516bSvtvF1EbmKiT4XuxnvRdQ449YyKXYgoEuUjtod7467zrVtmCFrTgsXWzPNZ6SuX3/<0;1>/*,[e3132379/44h/1h/0h]tpubDDkB59UH9e2jRnxNvUhm7yGqq3csxMHH4YFiHN4EyhwYsE4styvXFy3GvaYUG3JHHGkKbbyuR29hDcCxDEZ2m5sg77ov5HMt7VMHn27Dnav/<0;1>/*)),{and_v(v:after(1050000),multi_a(2,[93c34b55/44h/1h/0h]tpubDD637qigtWM7nJWDpG2bSNKtRwbwhsBhUSPBn2x7kwa4HQci697BpccQBy4aamu7vUuEgmHe9w9JTHjVnnj3ENdFC57xUaAHDipWqYRFf4M/<0;1>/*,[c9c90f7a/44h/1h/0h]tpubDCrZoKT5TeXQK66t9pXgZ4WZaLT1yy5rqY9Nev4oahSLY1x8GzqDqY1bs4MwVRCjJQEjKmw35saW24iyio7t2mfuy5dbffbe4cUTH5nuLfS/<0;1>/*,[ca5af974/44h/1h/0h]tpubDCszKRG2jLDx9pEePF6mnmxPwkNASFiJ5C65Gzw516bSvtvF1EbmKiT4XuxnvRdQ449YyKXYgoEuUjtod7467zrVtmCFrTgsXWzPNZ6SuX3/<0;1>/*,[e3132379/44h/1h/0h]tpubDDkB59UH9e2jRnxNvUhm7yGqq3csxMHH4YFiHN4EyhwYsE4styvXFy3GvaYUG3JHHGkKbbyuR29hDcCxDEZ2m5sg77ov5HMt7VMHn27Dnav/<0;1>/*)),and_v(v:after(1260000),multi_a(1,[93c34b55/44h/1h/0h]tpubDD637qigtWM7nJWDpG2bSNKtRwbwhsBhUSPBn2x7kwa4HQci697BpccQBy4aamu7vUuEgmHe9w9JTHjVnnj3ENdFC57xUaAHDipWqYRFf4M/<0;1>/*,[c9c90f7a/44h/1h/0h]tpubDCrZoKT5TeXQK66t9pXgZ4WZaLT1yy5rqY9Nev4oahSLY1x8GzqDqY1bs4MwVRCjJQEjKmw35saW24iyio7t2mfuy5dbffbe4cUTH5nuLfS/<0;1>/*,[ca5af974/44h/1h/0h]tpubDCszKRG2jLDx9pEePF6mnmxPwkNASFiJ5C65Gzw516bSvtvF1EbmKiT4XuxnvRdQ449YyKXYgoEuUjtod7467zrVtmCFrTgsXWzPNZ6SuX3/<0;1>/*,[e3132379/44h/1h/0h]tpubDDkB59UH9e2jRnxNvUhm7yGqq3csxMHH4YFiHN4EyhwYsE4styvXFy3GvaYUG3JHHGkKbbyuR29hDcCxDEZ2m5sg77ov5HMt7VMHn27Dnav/<0;1>/*))}}))"},
    }) {
        bilingual_str error;
        std::vector<bilingual_str> warnings;

        FlatSigningProvider keys;
        std::string parse_error;
        auto parsed = Parse(desc_str, keys, parse_error, /*require_checksum=*/false);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), parse_error);
        std::shared_ptr<Descriptor> descriptor{std::move(parsed.at(0))}; // receiving (/0) branch of the multipath descriptor
        const OutputType output_type{*Assert(descriptor->GetOutputType())};

        WalletDescriptor wallet_descriptor(descriptor, /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
        const uint256 legacy_id{LegacyDescriptorID(*descriptor)};
        // The stored (legacy) id and the current id must actually differ, or this exercises nothing.
        BOOST_REQUIRE(legacy_id != wallet_descriptor.id);

        // Expand index 0 to build the cache an old wallet would have persisted for this descriptor.
        FlatSigningProvider expand_provider;
        std::vector<CScript> expanded_scripts;
        FlatSigningProvider expanded_keys;
        BOOST_REQUIRE(descriptor->Expand(0, expand_provider, expanded_scripts, expanded_keys, &wallet_descriptor.cache));

        // Persist the descriptor record under the legacy id, as an older version would have. Use a
        // real (file-backed) database, not an in-memory mock, so the wallet can be reloaded below.
        const std::string wallet_name{"desc_id_mismatch_" + FormatOutputType(output_type)};
        DatabaseStatus status;
        DatabaseOptions create_options;
        create_options.require_create = true;
        std::unique_ptr<WalletDatabase> database{MakeWalletDatabase(wallet_name, create_options, status, error)};
        BOOST_REQUIRE(database);
        {
            WalletBatch batch(*database);
            BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED));
            BOOST_CHECK(batch.WriteDescriptor(legacy_id, wallet_descriptor));
            BOOST_CHECK(batch.WriteDescriptorCacheItems(legacy_id, wallet_descriptor.cache));
            BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(output_type), legacy_id, /*internal=*/false));
        }

        {
            const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), wallet_name, std::move(database)));
            // (a) The wallet loads despite the descriptor-id mismatch (it previously aborted as corrupt).
            BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
            // The descriptor remains keyed by the stored (legacy) id, not the recomputed one.
            BOOST_CHECK(wallet->GetScriptPubKeyMan(legacy_id) != nullptr);

            // (b) Re-importing the same descriptor must reuse the existing spkm, not add a second one.
            const size_t spkms_before{wallet->GetAllScriptPubKeyMans().size()};
            {
                LOCK(wallet->cs_wallet);
                WalletDescriptor reimport(descriptor, /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
                BOOST_CHECK(wallet->AddWalletDescriptor(reimport, keys, /*label=*/"", /*internal=*/false).has_value());
            }
            BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), spkms_before);

            // (c) getnewaddress works.
            BOOST_CHECK(wallet->GetNewDestination(output_type, /*label=*/"").has_value());
        }

        // (d) Reload from disk: the re-import must have updated the descriptor in place (under its
        // existing id) rather than writing a second record under the recomputed id, so the reloaded
        // wallet must still hold exactly one ScriptPubKeyMan.
        {
            DatabaseOptions reopen_options;
            reopen_options.require_existing = true;
            std::unique_ptr<WalletDatabase> reopened{MakeWalletDatabase(wallet_name, reopen_options, status, error)};
            BOOST_REQUIRE(reopened);
            const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), wallet_name, std::move(reopened)));
            BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
            BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), 1U);
            // The surviving manager is still the original, keyed by the legacy id (not migrated).
            BOOST_CHECK(wallet->GetScriptPubKeyMan(legacy_id) != nullptr);
        }

        // Control: the same dedup must hold for a normally-stored descriptor (record key == current
        // DescriptorID), confirming the content-based match doesn't regress the common path.
        {
            std::unique_ptr<WalletDatabase> database{CreateMockableWalletDatabase()};
            {
                WalletBatch batch(*database);
                BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED));
                BOOST_CHECK(batch.WriteDescriptor(wallet_descriptor.id, wallet_descriptor));
                BOOST_CHECK(batch.WriteDescriptorCacheItems(wallet_descriptor.id, wallet_descriptor.cache));
                BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(output_type), wallet_descriptor.id, /*internal=*/false));
            }
            const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
            BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
            const size_t spkms_before{wallet->GetAllScriptPubKeyMans().size()};
            {
                LOCK(wallet->cs_wallet);
                WalletDescriptor reimport(descriptor, /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
                BOOST_CHECK(wallet->AddWalletDescriptor(reimport, keys, /*label=*/"", /*internal=*/false).has_value());
            }
            BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), spkms_before);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
