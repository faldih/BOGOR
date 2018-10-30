-- Author : Muhammad Faldih
-- why haskell? gatau bingung

import qualified Control.Exception          as E
import           Control.Monad
import           Control.Monad.IO.Class
import           Data.Aeson                 (FromJSON)
import           Data.Either
import           Data.IORef
import           Data.List                  (find, nub)
import           Data.Maybe
import           Data.String.Utils
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import qualified Data.Yaml                  as Y
import           GHC.Generics               (Generic)
import           Servant
import           System.Console.CmdArgs
import           System.Directory
import           System.IO.HVFS
import qualified System.IO.Strict           as SIO
import           System.Path
import           System.Path.NameManip
import           Text.Blaze.Html5 (Html)
import qualified Text.Blaze.Html5           as BZ
import           Text.Printf
import           Text.Regex.Posix

newtype ToodlesConfig = ToodlesConfig
  { ignore :: [FilePath]
  } deriving (Show, Generic, FromJSON)  

app :: ToodlesState -> Application
app s = serve toodlesAPI server

    where
    server :: Server ToodlesAPI
    server = liftIO . getFullSearchResults s
        :<|> deleteTodos s
        :<|> editTodos s
        :<|> serveDirectoryFileServer (dataPath s)
        :<|> showRawFile s
        :<|> root s

root :: ToodlesState -> [Text] -> Handler Html
root (ToodlesState _ dPath) path =
    if null path then
        liftIO $ BZ.preEscapedToHtml <$> readFile (dPath ++ "/html/index.html")
    else throwError $ err404 { errBody = "Not found" }

showRawFile :: ToodlesState -> Integer -> Handler Html
showRawFile (ToodlesState ref _) eId = do
    (TodoListResult r _) <- liftIO $ readIORef ref
    let entry = find (\t -> entryId t == eId) r
    liftIO $
        maybe
        (return "Not found")
        (\e -> addAnchors <$> readFile (sourceFile e))
        entry

    where
    addAnchors :: String -> Html
    addAnchors s =
        let codeLines = zip [1::Int ..] $ lines s
        in BZ.preEscapedToHtml $
            (unlines $
            map
                (\(i, l) -> printf "<pre><a name=\"line-%s\">%s</a></pre>" (show i) l)
                codeLines)

editTodos :: ToodlesState -> EditTodoRequest -> Handler Text
editTodos (ToodlesState ref _) req = do
    (TodoListResult r _) <- liftIO $ readIORef ref
    let editedList = map
            (\t ->
                if willEditTodo req t
                then editTodo req t
                else t)
            r
        editedFilteredList = filter (willEditTodo req) editedList
    _ <- mapM_ recordUpdates editedFilteredList
    return "{}"
    where
    willEditTodo :: EditTodoRequest -> TodoEntry -> Bool
    willEditTodo editRequest entry = entryId entry `elem` editIds editRequest

    editTodo :: EditTodoRequest -> TodoEntry -> TodoEntry
    editTodo editRequest entry =
        let newAssignee = if isJust (setAssignee editRequest) && (not . T.null . fromJust $ setAssignee editRequest)
            then setAssignee editRequest
            else assignee entry
            newPriority = if isJust (setPriority editRequest) then setPriority editRequest else priority entry in

        entry {assignee = newAssignee,
                tags = tags entry ++ addTags editRequest,
                priority = newPriority,
                customAttributes = nub $ customAttributes entry ++ addKeyVals editRequest}

    recordUpdates :: MonadIO m => TodoEntry -> m ()
    recordUpdates t = void $ updateTodoLinesInFile renderTodo t

renderTodo :: TodoEntry -> [Text]
renderTodo t =
  let comment =
        fromJust $ lookup ("." <> getExtension (sourceFile t)) fileTypeToComment
      detail =
        "TODO (" <>
        (T.pack $
         Data.String.Utils.join
           "|"
           (map T.unpack $ [fromMaybe "" $ assignee t] ++
            listIfNotNull (fmap (T.pack . maybe "" ((\n -> "p=" ++ n) . show)) priority t) ++
            tags t ++
            map (\a -> fst a <> "=" <> snd a) (customAttributes t))) <>
        ") "
      fullNoComments = mapHead (\l -> detail <> "- " <> l) $ body t
      commented = map (\l -> comment <> " " <> l) fullNoComments in
      mapHead (\l -> leadingText t <> l) $
        mapInit (\l -> foldl (<>) "" [" " | _ <- [1..(T.length $ leadingText t)]] <> l) commented

    where
    mapHead :: (a -> a) -> [a] -> [a]
    mapHead f (x:xs) = f x : xs
    mapHead _ xs     = xs

    mapInit :: (a -> a) -> [a] -> [a]
    mapInit f (x:xs) = [x] ++ map f xs
    mapInit _ x      = x

    listIfNotNull :: Text -> [Text]
    listIfNotNull "" = []
    listIfNotNull s  = [s]

updateTodoLinesInFile :: MonadIO m => (TodoEntry -> [Text]) -> TodoEntry -> m ()
updateTodoLinesInFile f todo = do
  let startIndex = lineNumber todo - 1
      newLines = map T.unpack $ f todo
  fileLines <- liftIO $ lines <$> SIO.readFile (sourceFile todo)
  let updatedLines =
        slice 0 (fromIntegral $ startIndex - 1) fileLines ++ newLines ++
        (slice
           (fromIntegral startIndex + length (body todo))
           (length fileLines - 1)
           fileLines)
  liftIO $ writeFile (sourceFile todo) $ unlines updatedLines

    where
    slice :: Int -> Int -> [a] -> [a]
    slice a b xs = take (b - a + 1) (drop a xs)

deleteTodos :: ToodlesState -> DeleteTodoRequest -> Handler Text
deleteTodos (ToodlesState ref _) req = do
    refVal@(TodoListResult r _) <- liftIO $ readIORef ref
    let toDelete = filter (\t -> entryId t `elem` ids req) r
    liftIO $ doUntilNull removeAndAdjust toDelete
    let updeatedResults =
            refVal
            { todos =
                filter (\t -> entryId t `notElem` map entryId toDelete) r
            }
    _ <- liftIO $ atomicModifyIORef' ref (const (updeatedResults, updeatedResults))
    return "{}"

    where
    doUntilNull :: ([a] -> IO [a]) -> [a] -> IO ()
    doUntilNull f xs = do
        result <- f xs
        if null result
            then return ()
            else doUntilNull f result

    removeAndAdjust :: MonadIO m => [TodoEntry] -> m [TodoEntry]
    removeAndAdjust [] = return []
    removeAndAdjust (x:xs) = do
        removeTodoFromCode x
        forM xs $ \t -> return $
            if (sourceFile t == sourceFile x) && (lineNumber t > lineNumber x)
                then t { lineNumber = lineNumber t - (fromIntegral . length $ body x)}
                else t   

        where
        removeTodoFromCode :: MonadIO m => TodoEntry -> m ()
        removeTodoFromCode = updateTodoLinesInFile (const [])

setAbsolutePath :: ToodlesArgs -> IO ToodlesArgs
setAbsolutePath toodlesArgs = do
    let pathOrDefault = if T.null . T.pack $ directory toodlesArgs
                            then "."
                            else directory toodlesArgs
    absolute <- normalise_path <$> absolute_path pathOrDefault
    return $ toodlesArgs {directory = absolute}

getFullSearchResults :: ToodlesState -> Bool -> IO TodoListResult
getFullSearchResults (ToodlesState ref _) recompute =
  if recompute
    then do
      putStrLn "refreshing todo's"
      userArgs <- cmdArgs argParser >>= setAbsolutePath
      sResults <- runFullSearch userArgs
      atomicModifyIORef' ref (const (sResults, sResults))
    else putStrLn "cached read" >> readIORef ref

runFullSearch :: ToodlesArgs -> IO TodoListResult
runFullSearch userArgs = do
    let projectRoot = directory userArgs
    configExists <- doesFileExist $ projectRoot ++ "/.toodles.yaml"
    config <- if configExists
        then Y.decodeFileEither (projectRoot ++ "/.toodles.yaml")
        else return . Right $ ToodlesConfig []
    when (isLeft config)
        $ putStrLn $ "[WARNING] Invalid .toodles.yaml: " ++ show config
    allFiles <- getAllFiles (fromRight (ToodlesConfig []) config) projectRoot
    let parsedTodos = concatMap runTodoParser allFiles
        filteredTodos = filter (filterSearch (assignee_search userArgs)) parsedTodos
        resultList = limitSearch filteredTodos $ limit_results userArgs
        indexedResults = map (\(i, r) -> r {entryId = i}) $ zip [1 ..] resultList
    return $ TodoListResult indexedResults ""

    where
    filterSearch :: Maybe SearchFilter -> TodoEntry -> Bool
    filterSearch                                             Nothing     _ = True
    filterSearch (Just (AssigneeFilter (AssigneeFilterRegex query))) entry = fromMaybe "" (assignee entry) == query

    limitSearch :: [TodoEntry] -> Int -> [TodoEntry]
    limitSearch todoList 0 = todoList
    limitSearch todoList n = take n todoList

getAllFiles :: ToodlesConfig -> FilePath -> IO [SourceFile]
getAllFiles (ToodlesConfig ignoredPaths) basePath =
  E.catch
    (do putStrLn $ printf "Running toodles for path: %s" basePath
        files <- recurseDir SystemFS basePath
        let validFiles = filter isValidFile files
        mapM
          (\f ->
             SourceFile f . (map T.pack . lines) <$>
             E.catch
               (SIO.readFile f)
               (\(e :: E.IOException) -> print e >> return ""))
          validFiles)
    (\(e :: E.IOException) ->
       putStrLn ("Error reading " ++ basePath ++ ": " ++ show e) >> return [])

    where
    isValidFile :: FilePath -> Bool
    isValidFile path = fileHasValidExtension && not ignoreFile

        where
        fileHasValidExtension :: Bool
        fileHasValidExtension = any (\ext -> ext `T.isSuffixOf` T.pack path) (map fst fileTypeToComment)

        ignoreFile :: Bool
        ignoreFile =
            let p = T.pack path
            in T.isInfixOf "node_modules" p || T.isSuffixOf "pb.go" p ||
                T.isSuffixOf "_pb2.py" p ||
any (\r -> path =~ r :: Bool) ignoredPaths
