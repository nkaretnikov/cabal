{-# LANGUAGE RecordWildCards #-}

module Distribution.Client.OpenPGP where

import qualified Codec.Encryption.OpenPGP.ASCIIArmor as OpenPGPASCII
import Codec.Encryption.OpenPGP.ASCIIArmor.Types
  (Armor(Armor), ArmorType(ArmorPublicKeyBlock))
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Lazy  as BL
import qualified Data.ByteString.Char8 as C
import Codec.Encryption.OpenPGP.Fingerprint (fingerprint)
import Codec.Encryption.OpenPGP.KeyInfo (pubkeySize)
import Codec.Encryption.OpenPGP.Types
  ( TK(_tkUIDs, _tkKey), Pkt, TwentyOctetFingerprint(..)
  , PKPayload(_pkalgo, _pubkey, _timestamp), PubKeyAlgorithm )
import qualified Data.Conduit      as DC
import qualified Data.Conduit.List as CL
import Data.Conduit.OpenPGP.Keyring (conduitToTKs)
import Data.Serialize (runGetPartial, get, Result(Fail,Done))
import Control.Monad.Identity (runIdentity)
import Data.Time (UTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)

decodePublicKey :: C.ByteString -> Maybe [TK]
decodePublicKey bs =
  case OpenPGPASCII.decode bs :: Either String [Armor] of
    Right [(Armor ArmorPublicKeyBlock _ bs')]
      -> decodePublicKeyBody $ BL.toStrict bs'
    _ -> Nothing

decodePublicKeyBody :: BS.ByteString -> Maybe [TK]
decodePublicKeyBody bs = do
  pkts <- parsePublicKeyBody bs
  return $ runIdentity $ CL.sourceList pkts DC.$= conduitToTKs DC.$$ CL.consume

parsePublicKeyBody :: BS.ByteString -> Maybe [Pkt]
parsePublicKeyBody bs =
  go $ runGetPartial get bs
  where
    go (Fail _ _)      = Nothing
    go (Done pkt rest) = if BS.null rest
                         then return [pkt]
                         else do
                           pkts <- parsePublicKeyBody rest
                           return $ pkt : pkts

data PublicKeyInfo = PublicKeyInfo { pkUid          :: String
                                   , pkSize         :: Int
                                   , pkAlgorithm    :: PubKeyAlgorithm
                                   , pkFingerprint  :: TwentyOctetFingerprint
                                   , pkCreationDate :: UTCTime
                                   } deriving Show

maybePublicKeyInfo :: [TK] -> Maybe PublicKeyInfo
maybePublicKeyInfo []     = Nothing
maybePublicKeyInfo (tk:_) =  -- XXX: Is it a good idea to drop the rest?
  if not (null $ _tkUIDs tk) && isRight eitherSize
  then return $
    PublicKeyInfo { pkUid          = fst . head $ _tkUIDs tk
                  , pkSize         = fromRight eitherSize
                  , pkAlgorithm    = _pkalgo payload
                  , pkFingerprint  = fingerprint payload
                  , pkCreationDate = posixSecondsToUTCTime . realToFrac
                                   $ _timestamp payload
                  }
  else Nothing
  where
    payload    = fst $ _tkKey tk
    eitherSize = pubkeySize $ _pubkey payload
    isRight (Right _) = True
    isRight _         = False
    fromRight (Right v) = v

pprintPublicKeyInfo :: PublicKeyInfo -> String
pprintPublicKeyInfo PublicKeyInfo {..} = pkUid ++ "\n  "
                                      ++ show pkSize ++ " bit "
                                      ++ show pkAlgorithm ++ " key "
                                      ++ show pkFingerprint ++ ", "
                                      ++ "created: " ++ show pkCreationDate

isUntrustedKey :: PublicKeyInfo -> [C.ByteString] -> Bool
isUntrustedKey PublicKeyInfo{..} untrustedFingerprints =
  (C.pack $ show pkFingerprint) `elem` untrustedFingerprints
