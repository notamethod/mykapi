package com.notamethod.mkcore.certificate.profile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.notamethod.mkcore.utils.KeyUsages;
import com.notamethod.mkcore.certificate.MkCertificate;
import com.notamethod.mkcore.certificate.Certificate;


public class ProfileServices

{
    //TODO: manage CAs from PKI store too
    public static final Logger log = LogManager.getLogger(ProfileServices.class);
    private final static String PROFIL_EXTENSION = ".mkprof";
    private final String profilPath;

    public ProfileServices(String profilPath) {
        this.profilPath = profilPath;
    }

    public Properties loadProfile(String name) throws ProfilException {
        File f = new File(profilPath, name + PROFIL_EXTENSION);

        if (!f.exists()) {
            throw new ProfilException("Le profil n'existe pas");

        }
        try (FileInputStream fis = new FileInputStream(f)) {
            Properties p = new Properties();
            p.load(fis);
            return p;
        } catch (Exception e) {
            throw new ProfilException("Erreur chargement profil", e);
        }

    }

    public static List<? extends MkCertificate> getProfils(String cfgPath) {
        List<CertificateTemplate> profs = new ArrayList<>();

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get(cfgPath))) {
            for (Path path : directoryStream) {
                profs.add(new CertificateTemplate(path));
            }
        } catch (IOException ex) {
            log.error("can't load profile file",ex);
        }

        return profs;

    }

    public void saveToFile(Map<String, Object> elements, String name, Certificate certInfo, boolean isEditing)
            throws ProfilException, IOException {
        if (null == name || name.isBlank()) {
            throw new ProfilException("nom obligatoire");
        }
        File profDir = new File(profilPath);
        if (!profDir.exists()) {
            profDir.mkdirs();
        }
        File f = new File(profDir, name + PROFIL_EXTENSION);
        if (f.exists() && !isEditing) {
            throw new ProfilException("Profile already exists !");
        }
        Properties p = new Properties();
        for (Map.Entry<String, Object> entry : elements.entrySet()) {
            //log.debug("Key : " + entry.getKey() + " Value : " + entry.getValue());
            p.setProperty(entry.getKey(), (String) entry.getValue());
        }

        p.setProperty("&keyUsage", String.valueOf(KeyUsages.toInt(certInfo.getKeyUsage())));
        //noinspection ImplicitArrayToString
        p.setProperty("&keyUsage2", String.valueOf(certInfo.getKeyUsage()));
        try(FileOutputStream fos=new FileOutputStream(f)){
            p.store(fos, "");
        }
    }

    public String[] getProfiles() {
        File profDir = new File(profilPath);
        return profDir.list((dir, name) -> name.toLowerCase().endsWith(".mkprof"));
    }

    public void delete(CertificateTemplate certificateTemplate) throws IOException {
        Files.delete(certificateTemplate.getPath());

    }
}
