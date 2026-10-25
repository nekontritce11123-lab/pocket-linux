using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static class PortableEntry
{
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path,uint access,uint sharing,IntPtr security,uint creation,uint flags,IntPtr template);

    internal static string CreateShortcut(string root,string desktop)
    {
        root=Path.GetFullPath(root);desktop=Path.GetFullPath(desktop);
        string launcher=Path.Combine(root,"Launcher.exe");
        if(!File.Exists(launcher))throw new FileNotFoundException("Не найден Launcher.exe этой копии.",launcher);
        string target=Path.Combine(desktop,"Pocket Linux.lnk");
        string temporary=Path.Combine(desktop,Guid.NewGuid().ToString("N")+".lnk");
        object shell=null,link=null;
        var pins=new List<SafeFileHandle>();
        try
        {
            for(var parent=new DirectoryInfo(desktop);parent!=null;parent=parent.Parent)
            {
                if((parent.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Нельзя создать ярлык через папку-ссылку: "+parent.FullName);
                var handle=CreateFile(parent.FullName,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                if(handle.IsInvalid) {handle.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Нет доступа к папке рабочего стола.");}
                pins.Add(handle);
                if((File.GetAttributes(parent.FullName)&FileAttributes.ReparsePoint)!=0)throw new IOException("Папка рабочего стола изменилась. Повтори действие.");
            }
            if(File.Exists(target)||Directory.Exists(target))throw new IOException("Ярлык Pocket Linux уже существует. Переименуй или удали его самостоятельно, чтобы создать ярлык этой копии.");
            shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            link=shell.GetType().InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{temporary});
            link.GetType().InvokeMember("TargetPath",BindingFlags.SetProperty,null,link,new object[]{launcher});
            link.GetType().InvokeMember("WorkingDirectory",BindingFlags.SetProperty,null,link,new object[]{root});
            link.GetType().InvokeMember("IconLocation",BindingFlags.SetProperty,null,link,new object[]{launcher+",0"});
            link.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,link,null);
            File.Move(temporary,target);
            return target;
        }
        finally
        {
            try {if(link!=null)Marshal.FinalReleaseComObject(link);if(shell!=null)Marshal.FinalReleaseComObject(shell);if(File.Exists(temporary))File.Delete(temporary);}
            finally {foreach(var handle in pins)handle.Dispose();}
        }
    }
}
