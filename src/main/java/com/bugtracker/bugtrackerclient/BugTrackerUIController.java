package com.bugtracker.bugtrackerclient;

import com.bugtracker.bugtrackerclient.service.Bug;
import com.bugtracker.bugtrackerclient.service.BugTrackerConfiguration;
import com.bugtracker.bugtrackerclient.service.BugTrackerService;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class BugTrackerUIController {

    private final BugTrackerService trackerServ;

    public BugTrackerUIController(BugTrackerService trackerServ) {
        this.trackerServ = trackerServ;
    }

    @GetMapping("/")
    public String slash() {
        return "redirect:/bugtracker/ui";
    }

    @GetMapping("/bugtracker/ui")
    public ModelAndView home(
            OAuth2AuthenticationToken token,
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client) {

        OidcUser principal = (OidcUser)token.getPrincipal();

        ModelAndView model = generateDefaultModel(token);

        // Add accesstoken, refreshtoken and idtoken
        model.setViewName("home");
        model.addObject("accesstoken",
                BugTrackerUtils.prettyBody(client.getAccessToken().getTokenValue()));
        model.addObject("refreshtoken",
                BugTrackerUtils.prettyBody(client.getRefreshToken().getTokenValue()));
        model.addObject("idtoken",
                BugTrackerUtils.prettyBody(principal.getIdToken().getTokenValue()));
        return model;
    }

    @GetMapping("/bugtracker/ui/show-bugs")
    public ModelAndView showBugs(OAuth2AuthenticationToken token) {

        ModelAndView model = generateDefaultModel(token);

        model.setViewName("bugs");
        model.addObject("bugs", trackerServ.findAllBugs());
        return model;
    }

    @GetMapping("/bugtracker/ui/show-create-form")
    public ModelAndView showCreateForm(OAuth2AuthenticationToken token) {

        BugTrackerConfiguration cfg = trackerServ.getConfiguration();

        ModelAndView model = generateDefaultModel(token);

        model.setViewName("bug-form");
        model.addObject("bug", Bug.emptyBug(token.getName()));
        model.addObject("projects", cfg.projects());
        return model;
    }

    @PostMapping("/bugtracker/ui/save-bug")
    public String saveBug(OAuth2AuthenticationToken token,
                          @ModelAttribute Bug bug) {

        if (bug.id() == null)
            trackerServ.createBug(bug);
        else
            trackerServ.updateBug(bug);

        return "redirect:/bugtracker/ui/show-bugs";
    }

    @GetMapping("/bugtracker/ui/show-update-form")
    public ModelAndView showUpdateForm(OAuth2AuthenticationToken token,
                                       @RequestParam @NotNull Long bugId) {

        // Get the bug
        Bug bug = trackerServ.getBug(bugId);

        BugTrackerConfiguration cfg = trackerServ.getConfiguration();

        ModelAndView model = generateDefaultModel(token);
        model.setViewName("bug-form");
        model.addObject("bug", bug);
        model.addObject("projects", cfg.projects());
        return model;
    }

    @GetMapping("/bugtracker/ui/delete-bug")
    public String deleteBug(OAuth2AuthenticationToken token,
                            @RequestParam @NotNull Long bugId) {

        trackerServ.deleteBug(bugId);
        return "redirect:/bugtracker/ui/show-bugs";
    }

    @GetMapping("/bugtracker/ui/admin/show-edit-config")
    public ModelAndView showEditConfiguration(OAuth2AuthenticationToken token) {

        BugTrackerConfiguration cfg = trackerServ.getConfiguration();

        ModelAndView model = generateDefaultModel(token);
        model.setViewName("config-form");
        model.addObject("configuration", cfg);
        return model;
    }

    @PostMapping("/bugtracker/ui/admin/add-project")
    public String addProject(OAuth2AuthenticationToken token,
                             @RequestParam @NotEmpty String project) {

        trackerServ.addProject(project);
        return "redirect:/bugtracker/ui/admin/show-edit-config";
    }

    @GetMapping("/bugtracker/ui/admin/remove-project")
    public String removeProject(OAuth2AuthenticationToken token,
                                @RequestParam @NotEmpty String project) {

        trackerServ.removeProject(project);
        return "redirect:/bugtracker/ui/admin/show-edit-config";
    }


    /*
     * Sets some basic user information. The call can add more properties
     * to it before passing to the view file.
     */
    private ModelAndView generateDefaultModel(OAuth2AuthenticationToken token) {

        OidcUser principal = (OidcUser) token.getPrincipal();

        ModelAndView model = new ModelAndView();
        model.addObject("user", principal);
        return model;
    }

}
