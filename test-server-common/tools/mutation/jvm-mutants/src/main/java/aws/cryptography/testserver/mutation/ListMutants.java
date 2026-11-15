package aws.cryptography.testserver.mutation;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.pitest.classinfo.ClassByteArraySource;
import org.pitest.classinfo.ClassName;
import org.pitest.classpath.ClassPathByteArraySource;
import org.pitest.classpath.ClassloaderByteArraySource;
import org.pitest.classpath.CodeSource;
import org.pitest.classpath.DefaultCodeSource;
import org.pitest.mutationtest.EngineArguments;
import org.pitest.mutationtest.MutationConfig;
import org.pitest.mutationtest.build.CompoundInterceptorFactory;
import org.pitest.mutationtest.build.MutationInterceptor;
import org.pitest.mutationtest.build.MutationSource;
import org.pitest.mutationtest.build.TestPrioritiser;
import org.pitest.mutationtest.config.PluginServices;
import org.pitest.mutationtest.config.ReportOptions;
import org.pitest.mutationtest.engine.Mutater;
import org.pitest.mutationtest.engine.MutationDetails;
import org.pitest.mutationtest.engine.MutationEngine;
import org.pitest.mutationtest.engine.gregor.config.GregorEngineFactory;
import org.pitest.mutationtest.incremental.NullHistory;
import org.pitest.plugin.FeatureParser;

/**
 * Lists PIT's mutants of a library and writes each mutant's class file, for {@link MutantSwitch}.
 *
 * <p>Usage: {@code ListMutants <classpath.txt> <repo root> <source root>[:<source root>...] <out dir> [<lines>]}
 *
 * <p>{@code <lines>}, when given, keeps only mutants on the listed lines, one
 * {@code <file relative to the repo root><tab><line>} per line.
 *
 * <p>It reads the classes from the class path that MutantSwitch wrote, so the
 * mutants start from the bytes the server loads. The classes mutated are those
 * whose source file is under a source root. PIT's default mutators and its
 * default filters apply, the same as a {@code pitest-maven} run, so a mutant
 * that PIT leaves out (for example in a static initializer or a logging call)
 * is left out here too.
 *
 * <p>It writes {@code <out dir>/mutants.tsv}, one line per mutant: id, file
 * (relative to the repo root), line, mutator, method, method descriptor,
 * instruction indexes, class and description. The middle five name the
 * mutant the way a pitest-maven {@code mutations.xml} does. Ids
 * start at 1. The class file is {@code <out dir>/bytes/<id>/<class name>.class}.
 */
public final class ListMutants {

    private ListMutants() {
    }

    public static void main(String[] args) throws IOException {
        List<String> classPath = Arrays.asList(Files.readString(Path.of(args[0])).trim().split(File.pathSeparator));
        Path repo = Path.of(args[1]).toAbsolutePath().normalize();
        List<Path> sourceRoots = Stream.of(args[2].split(":")).map(root -> Path.of(root).toAbsolutePath().normalize())
            .toList();
        Path out = Path.of(args[3]);
        Set<String> lines = args.length > 4 ? new HashSet<>(Files.readAllLines(Path.of(args[4]))) : null;

        Set<String> packages = sourcePackages(sourceRoots);
        List<String> codePaths = new ArrayList<>();
        for (String entry : classPath) {
            if (holdsPackage(Path.of(entry), packages)) {
                codePaths.add(entry);
            }
        }

        ReportOptions options = new ReportOptions();
        options.setClassPathElements(classPath);
        options.setCodePaths(codePaths);
        options.setTargetClasses(packages.stream().map(name -> name.isEmpty() ? "*" : name + ".*").toList());
        // No test runs here; the Tests run against the server later.
        options.setTargetTests(List.of(name -> false));
        options.setMutators(List.of("DEFAULTS"));

        CodeSource code = new DefaultCodeSource(options.getMutationClassPaths());
        // JDK classes come from this JVM, as in a pitest-maven run.
        ClassByteArraySource fromClassPath = new ClassPathByteArraySource(options.getClassPath());
        ClassByteArraySource fromJdk = ClassloaderByteArraySource.fromContext();
        ClassByteArraySource classes = name -> fromClassPath.getBytes(name).or(() -> fromJdk.getBytes(name));
        TestPrioritiser noTests = details -> List.of();
        MutationEngine engine = new GregorEngineFactory().createEngine(
            EngineArguments.arguments().withMutators(options.getMutators()));
        MutationInterceptor filters = new CompoundInterceptorFactory(
                new FeatureParser().parseFeatures(options.getFeatures()),
                new ArrayList<>(PluginServices.makeForContextLoader().findInterceptors()))
            .createInterceptor(options, null, classes, noTests, code, new NullHistory());
        filters.initialise(code);
        MutationSource source = new MutationSource(new MutationConfig(engine, null), noTests, classes, filters);
        Mutater mutater = engine.createMutator(classes);

        Files.createDirectories(out);
        int id = 0;
        try (BufferedWriter tsv = Files.newBufferedWriter(out.resolve("mutants.tsv"), StandardCharsets.UTF_8)) {
            for (ClassName name : new TreeSet<>(code.getCodeUnderTestNames())) {
                for (MutationDetails mutant : source.createMutations(name)) {
                    String packagePath = name.getPackage().asInternalName();
                    Path file = sourceFile(sourceRoots, packagePath, mutant.getFilename());
                    if (file == null) {
                        continue;
                    }
                    String relative = repo.relativize(file).toString();
                    if (lines != null && !lines.contains(relative + "\t" + mutant.getLineNumber())) {
                        continue;
                    }
                    id++;
                    Path dir = Files.createDirectories(out.resolve("bytes").resolve(String.valueOf(id)));
                    Files.write(dir.resolve(name.asJavaName() + ".class"), mutater.getMutation(mutant.getId()).getBytes());
                    tsv.write(String.join("\t", String.valueOf(id), relative,
                        String.valueOf(mutant.getLineNumber()), mutant.getMutator(), mutant.getMethod(),
                        mutant.getId().getLocation().getMethodDesc(),
                        mutant.getId().getIndexes().stream().map(String::valueOf).collect(Collectors.joining(",")),
                        name.asJavaName(), mutant.getDescription().replace('\t', ' ').replace('\n', ' ')));
                    tsv.newLine();
                }
            }
        }
        System.out.println("[ListMutants] " + id + " mutants");
    }

    /** Packages, in dotted form, that hold a {@code .java} file under a source root. */
    private static Set<String> sourcePackages(List<Path> roots) throws IOException {
        Set<String> packages = new TreeSet<>();
        for (Path root : roots) {
            try (Stream<Path> files = Files.walk(root)) {
                files.filter(path -> path.toString().endsWith(".java")).forEach(path -> {
                    Path parent = root.relativize(path).getParent();
                    packages.add(parent == null ? "" : parent.toString().replace(File.separatorChar, '.'));
                });
            }
        }
        return packages;
    }

    /** Whether a class path entry holds a class directly in one of the packages. */
    private static boolean holdsPackage(Path entry, Set<String> packages) throws IOException {
        if (Files.isDirectory(entry)) {
            for (String name : packages) {
                Path dir = entry.resolve(name.replace('.', File.separatorChar));
                try (Stream<Path> files = Files.isDirectory(dir) ? Files.list(dir) : Stream.empty()) {
                    if (files.anyMatch(path -> path.toString().endsWith(".class"))) {
                        return true;
                    }
                }
            }
            return false;
        }
        if (!Files.isRegularFile(entry) || !entry.toString().endsWith(".jar")) {
            return false;
        }
        try (JarFile jar = new JarFile(entry.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                int slash = name.lastIndexOf('/');
                if (name.endsWith(".class") && packages.contains(slash < 0 ? "" : name.substring(0, slash).replace('/', '.'))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static Path sourceFile(List<Path> roots, String packagePath, String fileName) {
        for (Path root : roots) {
            Path file = root.resolve(packagePath).resolve(fileName);
            if (Files.isRegularFile(file)) {
                return file;
            }
        }
        return null;
    }
}
