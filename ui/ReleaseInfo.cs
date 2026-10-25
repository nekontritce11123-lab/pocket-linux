using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal sealed class ReleaseInfo
{
    internal readonly string ReleaseId, SourceCommit;
    internal string DisplayText { get { return ReleaseId == null ? "Версия для разработки" : "Версия " + ReleaseId; } }
    private ReleaseInfo(string releaseId = null,string sourceCommit = null) { ReleaseId=releaseId;SourceCommit=sourceCommit; }
    internal static ReleaseInfo Read(string root)
    {
        try
        {
            byte[] bytes=new byte[4097];int length;
            using(var stream=File.OpenRead(Path.Combine(root,"release-info.json")))
            {
                length=0;int read;
                while(length<bytes.Length&&(read=stream.Read(bytes,length,bytes.Length-length))>0)length+=read;
            }
            if(length>4096)return new ReleaseInfo();
            string json=new UTF8Encoding(false,true).GetString(bytes,0,length).TrimStart('\uFEFF');
            const string pair=@"""(?:schema|release_id|source_commit)""\s*:\s*(?:1|""[a-z0-9.]+"")";
            if(!Regex.IsMatch(json,@"\A\s*\{\s*"+pair+@"\s*,\s*"+pair+@"\s*,\s*"+pair+@"\s*\}\s*\z"))return new ReleaseInfo();
            var values=new JavaScriptSerializer{MaxJsonLength=4096}.Deserialize<Dictionary<string,object>>(json);
            object schema,id,commit;
            if(values.Count!=3||!values.TryGetValue("schema",out schema)||!(schema is int)||(int)schema!=1
                ||!values.TryGetValue("release_id",out id)||!(id is string)||!Regex.IsMatch((string)id,@"\A[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,8}\z")
                ||!values.TryGetValue("source_commit",out commit)||!(commit is string)||!Regex.IsMatch((string)commit,@"\A[a-f0-9]{40}\z"))return new ReleaseInfo();
            return new ReleaseInfo((string)id,(string)commit);
        }
        catch(Exception error)
        {
            if(!(error is IOException)&&!(error is UnauthorizedAccessException)&&!(error is SecurityException)&&!(error is ArgumentException)&&!(error is InvalidOperationException))throw;
            return new ReleaseInfo();
        }
    }
    internal static string StartupBlockReason(string root)
    {
        try
        {
            File.GetAttributes(Path.Combine(root,"state","app-update.json"));
            return "Обновление программы не завершено. Заверши или откати обновление перед открытием панели. Linux и данные не изменялись.";
        }
        catch(FileNotFoundException) { return null; }
        catch(DirectoryNotFoundException) { return null; }
        catch(Exception error)
        {
            if(!(error is IOException)&&!(error is UnauthorizedAccessException)&&!(error is SecurityException))throw;
            return "Не удалось проверить состояние обновления. Проверь доступ к папке программы перед открытием панели.";
        }
    }
}
